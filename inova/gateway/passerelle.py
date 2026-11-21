# -*- coding: utf-8 -*-
"""La passerelle de confidentialité (Presidio étendu au pentest).

    texte réel --(détecter)--(masquer)--(contrôler)--> SafePrompt --> cloud
    réponse    <--(réinjecter)------------------------------------- cloud

Principe "fail-closed" : si la détection est incertaine ou si une donnée
sensible subsiste après masquage, AUCUN SafePrompt n'est créé et l'appelant
retombe sur le modèle local. Une erreur de détection provoque donc un
repli local, jamais une fuite.
"""
from __future__ import annotations

import ipaddress
import re

import tldextract

# La passerelle ne doit faire AUCUN appel réseau : Presidio (via tldextract)
# essaie sinon de télécharger la liste des suffixes de domaine.
tldextract.tldextract.TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry  # noqa: E402
from presidio_analyzer.nlp_engine import NlpEngineProvider

from ..core.models import MaskResult, SafePrompt  # noqa: E402
from .recognizers import PENTEST_ENTITIES, build_pentest_recognizers  # noqa: E402
from .vault import Vault  # noqa: E402

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS"]
SPACY_MODELS = {"fr": "fr_core_news_sm", "en": "en_core_web_sm"}

# Mots techniques que le NER prend parfois pour des noms propres
ALLOW_LIST = ["SQL", "XSS", "CSRF", "SSRF", "RCE", "LFI", "IDOR", "CVE", "CVSS", "EPSS",
              "Apache", "Nginx", "PHP", "MySQL", "PostgreSQL", "OpenSSH", "WordPress",
              "Injection", "Faille", "Serveur", "Corriger", "Hôte", "Identifiant", "Contact",
              "Requête", "Analyse", "Vérification", "Impact", "Dépôt", "Authorization",
              "Responsable", "Jeton", "Clé", "Rédige", "Constat", "Actif", "Élément",
              "Autres", "Synthèse", "Pour"]
_DIGIT = re.compile(r"\d")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SECRET = re.compile(r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*(?!\[)\S+")


class Passerelle:
    def __init__(self, settings: dict, scope: dict, vault: Vault, language: str = "fr"):
        g = settings.get("gateway", {})
        self.min_conf = float(g.get("min_confidence", 0.60))
        self.band = float(g.get("uncertain_band", 0.35))
        self.max_uncertain = int(g.get("max_uncertain_spans", 0))
        self.language = language
        self.scope = scope
        self.vault = vault

        languages = list(SPACY_MODELS)
        nlp = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": l, "model_name": SPACY_MODELS[l]} for l in languages],
        }).create_engine()
        registry = RecognizerRegistry(supported_languages=languages)
        registry.load_predefined_recognizers(languages=languages, nlp_engine=nlp)
        for rec in build_pentest_recognizers(languages, scope):
            registry.add_recognizer(rec)
        self.analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp,
                                       supported_languages=languages)
        self.entities = PII_ENTITIES + PENTEST_ENTITIES

        t = scope.get("targets", {})
        self._networks = [ipaddress.ip_network(r, strict=False) for r in t.get("ip_ranges", [])]
        self._scope_terms = [x.lower() for x in t.get("domains", []) + scope.get("sensitive_terms", [])]

    # ------------------------------------------------------------------
    # 1) DÉTECTION
    # ------------------------------------------------------------------
    def analyze(self, text: str):
        results = self.analyzer.analyze(text=text, language=self.language,
                                        entities=self.entities, allow_list=ALLOW_LIST)
        results = [r for r in results if r.score >= self.band
                   and not self._false_person(r, text)]
        return self._merge_overlaps(results)

    @staticmethod
    def _false_person(r, text: str) -> bool:
        """Le NER prend parfois "Constat F-001" pour un nom : un nom ne contient pas de chiffre.
        (Les IP, URL, secrets... restent couverts par leurs propres détecteurs.)"""
        return r.entity_type == "PERSON" and bool(_DIGIT.search(text[r.start:r.end]))

    @staticmethod
    def _merge_overlaps(results):
        """Fusionne les détections qui se chevauchent en UNE zone englobante.

        Ex. CLIENT_TERM "intranet-demo" dans HOSTNAME "srv-db01.intranet-demo.local" :
        on masque tout le nom d'hôte, pour ne laisser aucun fragment en clair.
        La zone prend le type de la détection la plus sûre, et le score le plus
        BAS du groupe (prudence : une partie incertaine rend la zone incertaine).
        """
        groups = []
        for r in sorted(results, key=lambda r: r.start):
            if groups and r.start < groups[-1]["end"]:
                g = groups[-1]
                g["end"] = max(g["end"], r.end)
                g["members"].append(r)
            else:
                groups.append({"start": r.start, "end": r.end, "members": [r]})
        merged = []
        for g in groups:
            # type = la détection qui couvre toute la zone (plus parlant pour le cloud :
            # TARGET_URL plutôt que CLIENT_TERM), sinon la plus sûre
            covering = [m for m in g["members"] if m.start == g["start"] and m.end == g["end"]]
            best = max(covering or g["members"], key=lambda m: m.score)
            same_span = all(m.start == g["start"] and m.end == g["end"] for m in g["members"])
            best.start, best.end = g["start"], g["end"]
            # mêmes bornes : les détecteurs sont d'accord -> le plus sûr fait foi ;
            # bornes différentes : une partie douteuse rend la zone douteuse
            best.score = max(m.score for m in g["members"]) if same_span \
                else min(m.score for m in g["members"])
            if any(m.entity_type == "CLIENT_TERM" for m in g["members"]):
                best.score = max(best.score, 0.9)   # actif du client connu : certitude
            merged.append(best)
        return merged

    # ------------------------------------------------------------------
    # 2) MASQUAGE (avec jetons cohérents issus du vault)
    # ------------------------------------------------------------------
    def mask(self, text: str) -> MaskResult:
        return self.mask_detailed(text)[0]

    def mask_detailed(self, text: str) -> tuple[MaskResult, list[dict]]:
        """Comme mask(), et renvoie aussi chaque zone détectée (pour l'interface locale)."""
        results = self.analyze(text)
        uncertain = sum(1 for r in results if r.score < self.min_conf)
        # jetons attribués dans l'ordre de lecture ([X_1] avant [X_2])...
        tokens = []
        for r in results:
            entity = "TARGET_IP" if r.entity_type == "IP_ADDRESS" else r.entity_type
            tokens.append(self.vault.token_for(entity, text[r.start:r.end]))
        # ...puis remplacés de la fin vers le début (les index restent valides)
        masked = text
        for r, token in sorted(zip(results, tokens), key=lambda x: x[0].start, reverse=True):
            masked = masked[:r.start] + token + masked[r.end:]
        self.vault.save()
        spans = [{"start": r.start, "end": r.end, "entity": r.entity_type,
                  "score": round(r.score, 2), "certain": r.score >= self.min_conf, "token": t}
                 for r, t in zip(results, tokens)]
        result = MaskResult(masked_text=masked, nb_entities=len(results),
                            uncertain_spans=uncertain,
                            residual_leaks=self.residual_check(masked))
        return result, spans

    # ------------------------------------------------------------------
    # 3) CONTRÔLE APRÈS MASQUAGE (second filet de sécurité)
    # ------------------------------------------------------------------
    def residual_check(self, masked: str) -> list[str]:
        """Cherche ce qui aurait échappé au masquage.

        Retourne des CATÉGORIES (jamais les valeurs) pour pouvoir être journalisé.
        """
        leaks = []
        low = masked.lower()
        if any(term in low for term in self._scope_terms):
            leaks.append("TERME_DU_PERIMETRE")
        for ip in _IPV4.findall(masked):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            leaks.append("IP_DANS_LE_PERIMETRE" if any(addr in n for n in self._networks) else "IP")
        if _SECRET.search(masked):
            leaks.append("SECRET")
        return sorted(set(leaks))

    # ------------------------------------------------------------------
    # API utilisée par le reste d'INOVA
    # ------------------------------------------------------------------
    def to_safe_prompt(self, text: str) -> tuple[SafePrompt | None, MaskResult]:
        result = self.mask(text)
        ok = result.uncertain_spans <= self.max_uncertain and not result.residual_leaks
        return (SafePrompt(result.masked_text, self) if ok else None), result

    def restore(self, text: str) -> str:
        return self.vault.restore(text)
