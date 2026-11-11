# Validation de vulnérabilités avec Semgrep — Apache Tika

## Objectif

Configurer GitHub Actions pour détecter les nouvelles vulnérabilités introduites dans Apache Tika à l'aide de Semgrep. Le workflow utilise un scan différentiel afin de distinguer les nouvelles alertes de celles déjà présentes dans le projet.

## Configuration

Le workflow `.github/workflows/semgrep.yml` utilise Semgrep 1.185.0 et les règles `p/java`.

Il analyse trois modules :
- `tika-core`
- `tika-serialization`
- `tika-parsers/tika-parsers-ml/tika-parser-nlp-module`

L'option `--baseline-commit` permet de comparer les modifications avec la branche principale. L'option `--error` fait échouer le scan lorsqu'une nouvelle alerte est détectée.

## Vulnérabilités introduites

| Vulnérabilité | Règle Semgrep | Fichier |
|---|---|---|
| Hachage MD5 faible | `use-of-md5` | `SemgrepValidation.java` |
| Chiffrement DES obsolète | `des-is-deprecated` | `SemgrepValidation.java` |
| Injection SQL | `formatted-sql-string` | `SemgrepValidation.java` |
| Injection XML (XXE) | `saxparserfactory-disallow-doctype-decl-missing` | `SemgrepValidation.java` |
| Configuration TLS faible | `weak-ssl-context` | `SemgrepValidation.java` |
| Désérialisation Jackson non sécurisée | `jackson-unsafe-deserialization` | `JsonMergeUtils.java` |
| Requête HTTP non chiffrée | `httpget-http-request` | `GeoGazetteerClient.java` |

Ces modifications sont destinées à la démonstration et à la validation de l'analyse statique. Certaines ont été ajoutées dans des méthodes isolées.

## Résultats

| Analyse | Alertes |
|---|---:|
| Version initiale | 3 |
| Version modifiée | 10 |
| Nouvelles alertes (scan différentiel) | 7 |

Le scan différentiel local détecte les sept nouvelles alertes et retourne le code de sortie `1` avec `--error`.

La compilation Maven des modules concernés a également réussi.

## Rapports

- `apres.json` : toutes les alertes présentes dans les modules analysés.
- `nouvelles.json` : uniquement les alertes introduites depuis la version initiale.

## Reproduction

Depuis la racine du dépôt :

```bash
BASELINE=$(git merge-base HEAD origin/main)

semgrep scan \
  --config p/java \
  --baseline-commit "$BASELINE" \
  --error \
  tika-core tika-serialization \
  tika-parsers/tika-parsers-ml/tika-parser-nlp-module
```

Le scan différentiel a été validé localement. La validation de l'exécution GitHub Actions distante reste à confirmer.
