# IFT3913 — Tâche 3 : Analyse de sécurité avec Semgrep

## 1. Objectif

L'objectif de cette tâche est d'intégrer Semgrep dans un pipeline GitHub Actions afin de détecter automatiquement les nouvelles vulnérabilités introduites dans un projet Java.

Le projet utilisé est Apache Tika. Sept types de vulnérabilités ont été introduits volontairement dans des méthodes existantes des modules `tika-core` et `tika-serialization`.

Une deuxième partie du travail consiste à créer une action GitHub réutilisable dans GraphHopper pour afficher un Rickroll lorsqu'un test échoue.

## 2. Configuration de Semgrep

Le workflow `.github/workflows/semgrep.yml` exécute une analyse de sécurité différentielle.

Il utilise :
- Semgrep `1.185.0` ;
- les règles officielles `p/java` ;
- les règles personnalisées du dossier `semgrep-rules/` ;
- le commit de référence `2274b1126` ;
- l'option `--baseline-commit` pour identifier uniquement les nouvelles alertes ;
- l'option `--error` pour faire échouer le pipeline lorsqu'une nouvelle vulnérabilité est détectée.

Le workflow s'exécute sur GitHub Actions et conserve les résultats sous forme d'un artéfact JSON, même si l'analyse bloque le pipeline.

### Résultat obtenu

L'analyse différentielle a produit les résultats suivants :

| Indicateur | Résultat |
|---|---:|
| Règles exécutées | 64 |
| Fichiers analysés | 7 |
| Nouvelles alertes | 7 |
| Alertes bloquantes | 7 |
| Code de sortie | 1 |

Le message `Scan completed successfully` indique que l'analyse a été exécutée correctement. Le code de sortie `1` est ensuite provoqué volontairement par l'option `--error`, puisque sept nouvelles vulnérabilités ont été détectées.

**Preuve GitHub Actions :**  
[Exécution Semgrep — 7 alertes bloquantes](https://github.com/laylaelshahawy/tika/actions/runs/43151894517)

**Rapport généré :**  
[Artéfact semgrep-new-findings](https://github.com/laylaelshahawy/tika/actions/runs/43151894517/artifacts/13914441692)

## 3. Les sept vulnérabilités introduites

### 3.1 Injection de commandes — Command Injection

**Fichier :** `tika-core/src/main/java/org/apache/tika/detect/FileCommandDetector.java`

**Modification :** remplacement d'un `ProcessBuilder` utilisant des arguments séparés par une commande construite sous forme de chaîne et exécutée avec `sh -c`.

```java
String command = fileCommandPath + " -b --mime-type " + path.toAbsolutePath();
ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
```

**Risque :** si une valeur contrôlée par un utilisateur contient des caractères interprétés par le shell, elle peut modifier la commande exécutée. L'utilisation d'arguments séparés évitait cette interprétation.

**Détection :** règle Semgrep personnalisée `tika-shell-command-injection`.

### 3.2 Algorithme cryptographique faible — MD5

**Fichier :** `tika-core/src/main/java/org/apache/tika/digest/InputStreamDigester.java`

**Modification :** remplacement de l'algorithme demandé par MD5 lorsque le fournisseur cryptographique est nul.

```java
return MessageDigest.getInstance("MD5");
```

**Risque :** MD5 possède des faiblesses cryptographiques connues, notamment concernant les collisions. La modification crée aussi un problème fonctionnel : le programme peut calculer MD5 alors que l'appelant a demandé SHA-256.

**Détection :** règle officielle Semgrep `use-of-md5`.

**Test :** ajout de `testRequestedSha256IsActuallyUsed`, qui vérifie la valeur SHA-256 attendue. Ce test réussit sur la version de référence et échoue après l'introduction de la vulnérabilité.

### 3.3 Traversée de répertoires — Path Traversal

**Fichier :** `tika-core/src/main/java/org/apache/tika/io/FilenameUtils.java`

**Modification :** suppression de la normalisation du chemin avant de vérifier qu'il reste dans le répertoire autorisé.

```java
Path resolved = normalizedDir.resolve(name);
```

**Risque :** un chemin contenant `../` peut passer une vérification lexicale `startsWith()` alors qu'il pointe en réalité à l'extérieur du répertoire autorisé.

**Détection :** règle personnalisée `unsafe-path-resolution`.

**Test :** ajout de `testResolveWithinRejectsTraversalToMissingFile`, qui vérifie qu'un chemin de traversée vers un fichier inexistant est rejeté. Le test réussit sur la version de référence et échoue sur la version vulnérable.

### 3.4 Permissions non sécurisées sur les fichiers temporaires

**Fichier :** `tika-core/src/main/java/org/apache/tika/io/TemporaryResources.java`

**Modification :** ajout de l'instruction suivante après la création d'un fichier temporaire :

```java
path.toFile().setReadable(true, false);
```

**Risque :** le deuxième argument, `false`, permet d'étendre la permission de lecture au-delà du propriétaire du fichier sur les systèmes compatibles. Des fichiers temporaires contenant des informations sensibles pourraient ainsi être lus par d'autres utilisateurs.

**Détection :** règle personnalisée `insecure-temp-file-permissions`.

**Vérification :** un essai Java avec JShell a confirmé l'élargissement des permissions de lecture du fichier sur macOS.

### 3.5 Vérification HTTPS désactivée — Hostname Verification

**Fichier :** `tika-core/src/main/java/org/apache/tika/parser/NetworkParser.java`

**Modification :** ajout d'un vérificateur acceptant systématiquement le nom d'hôte pour les connexions HTTPS.

```java
if (connection instanceof HttpsURLConnection httpsConnection) {
    httpsConnection.setHostnameVerifier((hostname, session) -> true);
}
```

**Risque :** l'application ne vérifie plus correctement que le certificat présenté correspond au nom d'hôte demandé. Cela affaiblit l'authentification du serveur et peut faciliter certaines attaques de type homme du milieu.

La modification ne désactive toutefois pas à elle seule l'ensemble des autres vérifications TLS.

**Détection :** règle personnalisée `insecure-hostname-verification`.

### 3.6 Configuration XML non sécurisée — XXE

**Fichier :** `tika-core/src/main/java/org/apache/tika/utils/XMLReaderUtils.java`

**Modification :** remplacement de la fabrique SAX configurée par Tika par une nouvelle fabrique créée directement.

```java
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
```

**Risque :** cette modification contourne les protections de sécurité prévues dans la configuration de Tika. Selon la configuration effective du parseur, le traitement d'entités XML externes peut exposer l'application à des lectures de ressources non souhaitées ou à d'autres problèmes de sécurité.

**Détection :** règle officielle Semgrep `saxparserfactory-disallow-doctype-decl-missing`.

L'analyse statique signale cette configuration dangereuse. Aucun scénario d'exploitation XXE complet n'a été démontré.

### 3.7 Désérialisation Jackson non sécurisée

**Fichier :** `tika-serialization/src/main/java/org/apache/tika/config/loader/JsonMergeUtils.java`

**Modification :** remplacement du `ObjectMapper` fourni par un nouvel objet configuré avec le typage polymorphe par défaut.

```java
ObjectMapper unsafeMapper = new ObjectMapper();
unsafeMapper.enableDefaultTyping();
return unsafeMapper.readValue(json, configClass);
```

**Risque :** le typage polymorphe par défaut peut permettre à des données JSON de déterminer certains types Java instanciés. Selon le contexte d'utilisation, cela peut entraîner une désérialisation dangereuse. La modification ignore également les restrictions éventuelles du `ObjectMapper` initial.

**Détection :** règle officielle Semgrep `jackson-unsafe-deserialization`.

L'alerte a été détectée par Semgrep, sans démonstration d'une exploitation complète.

## 4. Comparaison avant et après

Les analyses ont été effectuées avec les mêmes ensembles de règles afin de comparer les résultats.

| Mesure | Nombre |
|---|---:|
| Alertes dans la version de référence | 3 |
| Alertes dans la version modifiée (analyse complète) | 10 |
| Nouvelles alertes détectées par analyse différentielle | 7 |

Trois alertes existaient déjà dans le code de référence :

- `MimeTypesReader.java` : configuration SAX potentiellement non sécurisée ;
- `NetworkParser.java` : utilisation d'une connexion non chiffrée ;
- `XMLReaderUtils.java` : configuration de `XMLInputFactory` potentiellement exposée aux XXE.

Ces trois alertes préexistantes ne sont pas comptées parmi les sept vulnérabilités introduites.

### Rapports enregistrés

- `rapports/semgrep-avant.json` : trois alertes présentes dans la version initiale ;
- `rapports/semgrep-apres.json` : sept nouvelles alertes issues de l'analyse différentielle.

Le rapport « après » enregistré dans le dépôt présente uniquement les nouvelles alertes, et non les dix alertes de l'analyse complète.

## 5. Règles officielles et personnalisées

Trois vulnérabilités ont été détectées par les règles officielles `p/java` :

- MD5 ;
- configuration SAX potentiellement vulnérable aux XXE ;
- désérialisation Jackson non sécurisée.

Quatre vulnérabilités ont été détectées par des règles personnalisées du dossier `semgrep-rules/` :

- injection de commandes ;
- traversée de répertoires ;
- permissions des fichiers temporaires ;
- vérification du nom d'hôte HTTPS.

Les règles personnalisées permettent de reconnaître des motifs dangereux précis dans le projet. Leur utilisation est complémentaire aux règles officielles, mais une alerte statique ne constitue pas à elle seule une preuve d'exploitation.

## 6. Tests et validation

Plusieurs méthodes de validation ont été utilisées.

**Tests Java :** les changements ont fait l'objet de vérifications Maven et de tests ciblés.

**Tests de régression :** deux tests ont été ajoutés pour démontrer des comportements incorrects :

- `testRequestedSha256IsActuallyUsed`, pour le calcul MD5 malgré une demande SHA-256 ;
- `testResolveWithinRejectsTraversalToMissingFile`, pour la traversée de répertoires.

Ces tests échouent volontairement sur la version vulnérable.

**Essais JShell :** des essais locaux ont permis de vérifier l'effet de la normalisation des chemins et de l'élargissement des permissions d'accès aux fichiers temporaires.

**GitHub Actions :** le workflow Semgrep a détecté les sept nouvelles vulnérabilités et a terminé avec un statut d'échec attendu. L'artéfact JSON a été généré.

## 7. Action réutilisable Rickroll dans GraphHopper

Une action composite GitHub a été créée dans un fork de GraphHopper.

**Dépôt :**  
https://github.com/laylaelshahawy/graphhopper

**Branche principale du travail :** `tache3-rickroll`

**Action réutilisable :** `.github/actions/rickroll/action.yml`

**Workflow :** `.github/workflows/rickroll.yml`

Le workflow exécute les tests Java `ReaderElementTest`, puis appelle l'action composite uniquement si l'étape de test échoue :

```yaml
- name: Rickroll on test failure
  if: ${{ failure() && steps.tests.outcome == 'failure' }}
  uses: ./.github/actions/rickroll
```

### Validation

Deux scénarios ont été vérifiés dans GitHub Actions :

| Scénario | Résultat |
|---|---|
| Trois tests Java réussis | Workflow réussi, Rickroll ignoré |
| Échec simulé de l'étape de tests | Workflow échoué, Rickroll exécuté |

Lors du second scénario, l'étape `Run GraphHopper test` s'est terminée avec `exit code 1`. L'étape `Rickroll on test failure` a ensuite affiché le message `Never gonna give you up!`.

Ce scénario démontre le déclenchement de l'action réutilisable à la suite d'un échec simulé, et non d'une assertion Java réellement échouée.

Une documentation complémentaire est disponible dans `RICKROLL.md` sur la branche `tache3-rickroll`.

**Exécutions GitHub Actions :**  
https://github.com/laylaelshahawy/graphhopper/actions

## 8. Conclusion

Les sept vulnérabilités ont été introduites dans des méthodes existantes d'Apache Tika, puis détectées par une combinaison de règles Semgrep officielles et personnalisées.

L'analyse différentielle a distingué les sept nouveaux problèmes des trois alertes déjà présentes dans le code de référence.

Le workflow GitHub Actions a correctement bloqué les modifications vulnérables et conservé le rapport de détection sous forme d'artéfact.

Enfin, l'action réutilisable GraphHopper a été validée à l'aide d'un scénario de réussite des tests et d'un scénario d'échec simulé déclenchant le Rickroll.

## 9. Utilisation de l'intelligence artificielle

ChatGPT (OpenAI) a été utilisé comme outil d'assistance pour la compréhension des consignes, l'analyse des vulnérabilités, la configuration et le débogage de Semgrep et de GitHub Actions, ainsi que la rédaction de la documentation.

Les modifications apportées au code ont été vérifiées à l'aide de tests locaux et des résultats de GitHub Actions. Les résultats et les observations présentés dans ce rapport correspondent aux vérifications effectuées dans le cadre du travail.
