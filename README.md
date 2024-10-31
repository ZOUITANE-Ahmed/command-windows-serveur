# command-windows-serveur

### I. Configuration de base


Créer un utilisateur dans Active Directory peut se faire de différentes manières, notamment via l’interface graphique de la console « Utilisateurs et ordinateurs Active Directory » ou en utilisant PowerShell pour l'automatisation. Voici les méthodes les plus courantes :

---

### I. Créer un utilisateur avec la console « Utilisateurs et ordinateurs Active Directory »

1. **Ouvrir la console Active Directory**
   - Allez dans le menu **Démarrer** > **Outils d’administration** > **Utilisateurs et ordinateurs Active Directory**.

2. **Naviguer jusqu’à l’unité organisationnelle (OU)**
   - Accédez à l'OU où vous souhaitez créer l’utilisateur.

3. **Créer un nouvel utilisateur**
   - Faites un clic droit dans la zone de travail > **Nouveau** > **Utilisateur**.
   - Remplissez les informations de base : nom, nom d’utilisateur (sAMAccountName).
   - Cliquez sur **Suivant**, définissez le mot de passe et configurez les options de mot de passe (exemple : l'utilisateur doit changer le mot de passe à la prochaine connexion).
   - Cliquez sur **Terminer** pour finaliser la création.

---

### II. Créer un utilisateur avec PowerShell

#### 1. **Créer un utilisateur de base**
   ```powershell
   New-ADUser -Name "Nom Complet" -GivenName "Prénom" -Surname "Nom" -SamAccountName "NomUtilisateur" -UserPrincipalName "NomUtilisateur@exemple.com" -Path "OU=Utilisateurs,DC=exemple,DC=com" -AccountPassword (ConvertTo-SecureString "MotDePasse123!" -AsPlainText -Force) -Enabled $true
   ```
   *Ce script crée un utilisateur avec les informations de base, dans l’OU spécifiée, avec un mot de passe défini.*

#### 2. **Créer un utilisateur avec des attributs supplémentaires**
   ```powershell
   New-ADUser -Name "Nom Complet" -GivenName "Prénom" -Surname "Nom" -SamAccountName "NomUtilisateur" -UserPrincipalName "NomUtilisateur@exemple.com" -Path "OU=Utilisateurs,DC=exemple,DC=com" -AccountPassword (ConvertTo-SecureString "MotDePasse123!" -AsPlainText -Force) -Enabled $true -Office "Bureau" -Department "Département" -Title "TitrePoste" -Description "Description de l'utilisateur"
   ```
   *Ajoute des informations supplémentaires comme le bureau, le département, et le titre de poste.*

---

### III. Créer plusieurs utilisateurs à partir d’un fichier CSV

Pour créer plusieurs utilisateurs à partir d’un fichier, suivez les étapes suivantes.

#### 1. **Créer le fichier CSV**
   - Créez un fichier `utilisateurs.csv` avec les colonnes suivantes : `Name`, `GivenName`, `Surname`, `SamAccountName`, `UserPrincipalName`, `Path`, `Password`.

   Exemple de contenu du fichier CSV :
   ```csv
   Name,GivenName,Surname,SamAccountName,UserPrincipalName,Path,Password
   Jean Dupont,Jean,Dupont,JDupont,jdupont@exemple.com,"OU=Utilisateurs,DC=exemple,DC=com",MotDePasse123!
   Marie Martin,Marie,Martin,MMartin,mmartin@exemple.com,"OU=Utilisateurs,DC=exemple,DC=com",MotDePasse123!
   ```

#### 2. **Script PowerShell pour importer les utilisateurs**
   ```powershell
   Import-Csv -Path "C:\chemin\utilisateurs.csv" | ForEach-Object {
       New-ADUser -Name $_.Name -GivenName $_.GivenName -Surname $_.Surname -SamAccountName $_.SamAccountName -UserPrincipalName $_.UserPrincipalName -Path $_.Path -AccountPassword (ConvertTo-SecureString $_.Password -AsPlainText -Force) -Enabled $true
   }
   ```
   *Ce script importe chaque ligne du fichier CSV et crée un utilisateur dans AD avec les informations fournies.*

---

### IV. Activer et forcer le changement de mot de passe à la prochaine connexion

Si vous avez déjà créé l’utilisateur mais souhaitez qu’il change son mot de passe à sa première connexion, utilisez la commande suivante :

   ```powershell
   Set-ADUser -Identity "NomUtilisateur" -PasswordNeverExpires $false
   Set-ADUser -Identity "NomUtilisateur" -ChangePasswordAtLogon $true
   ```

---

### V. Exemple complet de création d’utilisateur avec un script PowerShell

Voici un script complet qui peut être modifié pour des tâches spécifiques :

   ```powershell
   $nomComplet = "Pierre Durand"
   $prenom = "Pierre"
   $nom = "Durand"
   $samAccountName = "PDurand"
   $userPrincipalName = "pdurand@exemple.com"
   $ouPath = "OU=Utilisateurs,DC=exemple,DC=com"
   $password = ConvertTo-SecureString "MotDePasse123!" -AsPlainText -Force

   New-ADUser -Name $nomComplet -GivenName $prenom -Surname $nom -SamAccountName $samAccountName -UserPrincipalName $userPrincipalName -Path $ouPath -AccountPassword $password -Enabled $true
   ```

Ce script crée l’utilisateur avec tous les détails requis et est prêt à être exécuté pour ajouter directement un nouvel utilisateur dans Active Directory.

---

Ces méthodes permettent de gérer facilement la création d’utilisateurs dans Active Directory, qu’il s’agisse de créer un seul utilisateur ou d’en importer plusieurs depuis un fichier CSV. N’hésitez pas à personnaliser ces commandes selon les besoins spécifiques de votre organisation.

----
1. **Changer le mot de passe utilisateur :**
   ```powershell
   $Password = Read-Host -AsSecureString "nouveau mot de passe" 
   Set-LocalUser -Name "NomDuCompte" -Password $Password
   ```

2. **Affichage et configuration IP :**
   ```powershell
   Get-NetIPAddress
   New-NetIPAddress -InterfaceAlias "Nom Interface" -IPAddress "Adresse IP" -PrefixLength 24 -DefaultGateway "Passerelle"
   ```

3. **Installer des rôles et fonctionnalités :**
   ```powershell
   Install-WindowsFeature "Nom"
   ```

4. **Basculer entre Server Core et GUI (pour Windows Server 2012 et 2012 R2 uniquement) :**
   ```powershell
   # Passer de Core à GUI
   Install-WindowsFeature Server-Gui-Shell, Server-Gui-Mgmt-Infra -Restart

   # Passer de GUI à Core
   Uninstall-WindowsFeature Server-Gui-Shell, Server-Gui-Mgmt-Infra –Restart
   ```

5. **Activer la réception des commandes à distance et établir des sessions distantes :**
   ```powershell
   Enable-PSRemoting -Force
   Enter-PSSession -ComputerName "Adresse IP"
   ```

6. **Connexion à Azure :**
   ```powershell
   Connect-AzAccount
   Get-AzVM
   ```

---

### II. Rôles et fonctionnalités
1. **Lister les rôles disponibles et installer des fonctionnalités :**
   ```powershell
   Get-WindowsFeature
   Install-WindowsFeature –Name "Nom" -ComputerName "Serveur" -restart
   ```

2. **Désinstaller des fonctionnalités et redémarrer le serveur :**
   ```powershell
   Uninstall-WindowsFeature –Name "Nom" -ComputerName "Serveur" –Remove
   Restart-Computer -ComputerName "Serveur"
   ```

3. **Installation de Windows Admin Center (WAC) :**
   ```powershell
   msiexec /i <path_to_WAC_installer.msi>
   ```

---

### III. Active Directory et DC
1. **Gestion du service Active Directory :**
   ```powershell
   net stop ntds
   net start ntds
   ```

2. **Diagnostics et réplication Active Directory :**
   ```powershell
   dcdiag /V /C /D /E > c:\dcdiag.txt
   repadmin /showrepl
   ```

3. **Lister les rôles FSMO et vérifier la réplication :**
   ```powershell
   netdom query fsmo
   dcdiag /test:replications
   ```

4. **Promotion en tant que contrôleur de domaine et installation d’AD DS :**
   ```powershell
   Install-WindowsFeature -Name AD-Domain-Services –IncludeManagementTools
   Install-ADDSForest -DomainName "cmc.Local" -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "7" -DomainNetbiosName "CMC" -ForestMode "7" -InstallDns:$true -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -Force:$true
   ```

---

### IV. Transfert des rôles FSMO
1. **Vérification et transfert des rôles FSMO :**
   ```powershell
   Get-ADDomain | Select-Object PDCEmulator
   Move-ADDirectoryServerOperationMasterRole -Identity "Serveur" -OperationMasterRole PDCEmulator
   ```

---

### V. Clonage de contrôleur de domaine
1. **Préparer et créer un fichier de clonage :**
   ```powershell
   Add-ADDCCloneAllowed –Identity “Nom DC Source”
   New-ADDCCloneConfigFile -Static -CloneComputerName "Nom DC Cloned" -SiteName "SiteCible" -IPv4Address "@IP" -IPvDNSResolver "DNS-IP" -IPv4SubnetMask "Mask"
   ```

---

### VI. Groupes et Utilisateurs
1. **Création et suppression de groupes :**
   ```powershell
   New-ADGroup -GroupCategory Security -GroupScope Global -Name "NomGroupe" -Path "OU=DIA,DC=cmc,DC=local" -SamAccountName "IDOSR" -Description "Groupe des Stagiaires"
   Remove-ADGroup -Identity "NomGroupe" -Confirm:$false
   ```

2. **Création, suppression, et récupération des utilisateurs :**
   ```powershell
   New-ADUser -Name "Nom" -SamAccountName "Nom" -UserPrincipalName "Nom@cmc.local" -Path "OU=Utilisateurs,DC=cmc,DC=local" -AccountPassword (ConvertTo-SecureString "Password" -AsPlainText -Force) -Enabled $true
   Remove-ADUser -Identity "Nom" -Confirm:$false
   ```

---

Voici une présentation simplifiée des commandes de gestion des unités organisationnelles (OU) dans Active Directory en français.

---

### I. Commandes de base pour les OU

#### 1. **Créer une OU**
   ```powershell
   New-ADOrganizationalUnit -Name "NomOU" -Path "DC=exemple,DC=com"
   ```
   *Crée une unité organisationnelle (OU) à l’emplacement spécifié.*

#### 2. **Supprimer une OU**
   ```powershell
   Remove-ADOrganizationalUnit -Identity "OU=NomOU,DC=exemple,DC=com" -Confirm:$false
   ```
   *Supprime une OU sans confirmation.*

#### 3. **Renommer une OU**
   ```powershell
   Rename-ADObject -Identity "OU=AncienNom,DC=exemple,DC=com" -NewName "NouveauNom"
   ```
   *Renomme une OU avec un nouveau nom.*

#### 4. **Déplacer une OU**
   ```powershell
   Move-ADObject -Identity "OU=SourceOU,DC=exemple,DC=com" -TargetPath "OU=CibleOU,DC=exemple,DC=com"
   ```
   *Déplace une OU vers une autre unité parente.*

---

### II. Sécurité et permissions pour les OU

#### 1. **Déléguer des permissions pour une OU**
   *Utilisez l’interface graphique de "Utilisateurs et ordinateurs Active Directory" pour attribuer des permissions spécifiques aux utilisateurs/groupes sur une OU.*

#### 2. **Définir des permissions d’OU via PowerShell**
   ```powershell
   $ACL = Get-Acl -Path "AD:\OU=NomOU,DC=exemple,DC=com"
   # Modifiez $ACL selon les besoins, puis appliquez les permissions
   Set-Acl -Path "AD:\OU=NomOU,DC=exemple,DC=com" -AclObject $ACL
   ```
   *Ajuste les permissions sur une OU par programmation.*

---

### III. Lister et exporter les informations d’OU

#### 1. **Lister toutes les OU du domaine**
   ```powershell
   Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
   ```
   *Récupère toutes les OU avec leurs noms et noms distinctifs.*

#### 2. **Exporter la structure d'OU en CSV**
   ```powershell
   Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName | Export-Csv -Path "C:\OUs.csv" -NoTypeInformation
   ```
   *Exporte la hiérarchie des OU dans un fichier CSV pour documentation.*

---

### IV. Appliquer des stratégies de groupe à une OU

#### 1. **Lier une GPO à une OU**
   ```powershell
   New-GPLink -Name "NomGPO" -Target "OU=NomOU,DC=exemple,DC=com"
   ```
   *Associe un objet de stratégie de groupe (GPO) spécifique à une OU.*

#### 2. **Retirer un lien GPO d’une OU**
   ```powershell
   Remove-GPLink -Name "NomGPO" -Target "OU=NomOU,DC=exemple,DC=com"
   ```
   *Supprime un lien GPO existant de la OU spécifiée.*

#### 3. **Lister les GPO liés à une OU**
   ```powershell
   Get-GPInheritance -Target "OU=NomOU,DC=exemple,DC=com"
   ```
   *Liste les GPO appliqués à la OU spécifiée.*

---

### V. Gestion des objets dans une OU

#### 1. **Créer un utilisateur dans une OU**
   ```powershell
   New-ADUser -Name "NomUtilisateur" -Path "OU=NomOU,DC=exemple,DC=com" -SamAccountName "NomUtilisateur" -UserPrincipalName "NomUtilisateur@exemple.com" -AccountPassword (ConvertTo-SecureString "MotDePasse" -AsPlainText -Force) -Enabled $true
   ```
   *Crée un nouvel utilisateur dans une OU spécifique.*

#### 2. **Déplacer des utilisateurs ou ordinateurs vers une OU**
   ```powershell
   Move-ADObject -Identity "CN=NomUtilisateur,DC=exemple,DC=com" -TargetPath "OU=NomOU,DC=exemple,DC=com"
   ```
   *Déplace un utilisateur ou un ordinateur existant vers une OU cible.*

#### 3. **Lister tous les utilisateurs dans une OU**
   ```powershell
   Get-ADUser -Filter * -SearchBase "OU=NomOU,DC=exemple,DC=com" | Select-Object Name, SamAccountName
   ```
   *Liste tous les utilisateurs dans une OU spécifiée.*

---

Ces étapes couvrent les commandes essentielles pour gérer les unités organisationnelles dans un environnement Active Directory. N'hésitez pas si vous avez besoin de plus de détails ou d'exemples spécifiques.

|A|B|C|
|-|-|-|
|Créer des groupes dans une OU|Déployer des GPO avancées|Scripts de gestion pour Active Directory|

---

### VII. DHCP
1. **Installation et configuration de DHCP :**
   ```powershell
   Install-WindowsFeature -Name DHCP -IncludeManagementTools
   Add-DhcpServerInDC -DnsName "NomDuServeur" -IPAddress "Adresse_IP_du_Serveur"
   ```

2. **Création d’étendues et réservations DHCP :**
   ```powershell
   Add-DhcpServerv4Scope -Name "Etendue1" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0 -State Active
   Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.120 -ClientId "00-11-22-33-44-55" -Description "Réservation pour un client spécifique"
   ```

---

### VIII. Automatisation avec CSV / LDIFDE
1. **Importation et exportation via CSVDE et LDIFDE :**
   ```powershell
   # CSVDE
   csvde -i -f c:\import.csv
   csvde -f c:\export.csv

   # LDIFDE
   ldifde -i -f c:\import.ldf
   ldifde -f c:\export.ldf
   ```

---

Les objets de stratégie de groupe (GPO) sont des outils puissants pour configurer les environnements utilisateur et ordinateur dans Active Directory. Voici un guide de base en français sur la gestion des GPO.

---

### I. Créer et configurer une GPO

#### 1. **Créer une nouvelle GPO**
   ```powershell
   New-GPO -Name "NomGPO" -Comment "Description de la GPO"
   ```
   *Crée une GPO avec un nom et une description.*

#### 2. **Lier une GPO à une OU**
   ```powershell
   New-GPLink -Name "NomGPO" -Target "OU=NomOU,DC=exemple,DC=com"
   ```
   *Associe la GPO à une unité organisationnelle spécifique.*

#### 3. **Modifier les paramètres d'une GPO**
   *Utilisez le "Group Policy Management Console (GPMC)" (ou Console de gestion des stratégies de groupe) pour configurer les paramètres utilisateur ou ordinateur de la GPO.*

---

### II. Contrôler les droits et les permissions

#### 1. **Déléguer les droits de gestion d'une GPO**
   ```powershell
   Set-GPPermission -Name "NomGPO" -TargetName "GroupeOuUtilisateur" -TargetType Group -PermissionLevel GpoEdit
   ```
   *Donne des droits spécifiques (ex. : GpoEdit) à un groupe ou un utilisateur sur une GPO.*

#### 2. **Restreindre l'application de la GPO à certains utilisateurs ou groupes**
   *Utilisez la fonctionnalité de "Filtrage de sécurité" dans la GPMC pour définir quels utilisateurs ou groupes doivent appliquer la GPO.*

---

### III. Paramètres et préférences des GPO

Les GPO peuvent être utilisées pour configurer divers paramètres, notamment :

- **Politiques de sécurité** : Configurer les mots de passe, verrouillage de session, etc.
- **Stratégies de restriction logicielle** : Définir quels logiciels peuvent être exécutés sur les ordinateurs.
- **Configuration réseau** : Attribuer des configurations de proxy, de pare-feu, et de réseau.
- **Bureau et environnement utilisateur** : Configurer le fond d'écran, les icônes de bureau, les paramètres du menu Démarrer, etc.
- **Scripts de démarrage et d’arrêt** : Exécuter des scripts pour automatiser les tâches au démarrage ou à l’arrêt.

### IV. Gérer l’héritage et le filtrage

#### 1. **Bloquer l’héritage de GPO**
   ```powershell
   Set-GPInheritance -Target "OU=NomOU,DC=exemple,DC=com" -IsBlocked $true
   ```
   *Empêche une OU de recevoir les GPO appliquées aux niveaux supérieurs.*

#### 2. **Appliquer une GPO de manière forcée (Forcer l’héritage)**
   ```powershell
   Set-GPLink -Name "NomGPO" -Target "OU=NomOU,DC=exemple,DC=com" -Enforced Yes
   ```
   *Force l'application de la GPO, même si d'autres GPO sont bloquées.*

---

### V. Rapports et dépannage

#### 1. **Générer un rapport HTML pour une GPO**
   ```powershell
   Get-GPOReport -Name "NomGPO" -ReportType Html -Path "C:\RapportGPO.html"
   ```
   *Génère un rapport détaillé des paramètres configurés dans une GPO.*

#### 2. **Vérifier les GPO appliquées à un utilisateur ou ordinateur spécifique**
   ```powershell
   gpresult /R /Scope User
   gpresult /R /Scope Computer
   ```
   *Affiche les GPO appliquées pour un utilisateur ou un ordinateur.*

---

### VI. Supprimer et restaurer une GPO

#### 1. **Supprimer une GPO**
   ```powershell
   Remove-GPO -Name "NomGPO"
   ```
   *Supprime la GPO spécifiée du domaine.*

#### 2. **Sauvegarder et restaurer une GPO**
   - **Sauvegarde :**
     ```powershell
     Backup-GPO -Name "NomGPO" -Path "C:\BackupGPO"
     ```
     *Sauvegarde une GPO dans le chemin spécifié.*
   - **Restauration :**
     ```powershell
     Restore-GPO -Name "NomGPO" -Path "C:\BackupGPO"
     ```
     *Restaure une GPO depuis une sauvegarde.*

---

### Exemples d'application

- **Bloquer l'accès au Panneau de configuration** : Configurez une GPO pour restreindre l'accès via les paramètres utilisateur.
- **Installation de logiciels** : Utilisez des GPO pour déployer des logiciels via des packages MSI.
- **Personnalisation du bureau** : Changez le fond d’écran de tous les utilisateurs.

---

Les GPO permettent une gestion centralisée et un contrôle accru de l'environnement utilisateur et système dans un domaine Active Directory. N'hésitez pas si vous avez besoin de conseils supplémentaires pour la configuration ou le dépannage de GPO spécifiques.

---
Cette structure regroupe les principales commandes par catégorie pour vous aider à organiser votre gestion d’Active Directory, des rôles, et des services associés.
