# 1️⃣ Přejít do složky s aktuálním projektem
cd /mnt/ssd

# 2️⃣ Vytvořit novou složku pro GitHub verzi
mkdir OfficeGit

# 3️⃣ Zkopírovat všechny soubory kromě těch, které nechceme podle .gitignore
rsync -av --progress office/ OfficeGit \
    --exclude 'bin/' \
    --exclude 'include/' \
    --exclude 'lib/' \
    --exclude 'cloud_storage/' \
    --exclude 'users.db' \
    --exclude 'úvod.txt' \
    --exclude 'nohup.out' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'pyvenv.cfg' \
    --exclude '*.fossil' \
    --exclude '.fslckout'

# 4️⃣ Přejít do nové složky
cd OfficeGit

# 5️⃣ Inicializace Git a přidání remote
git init
git remote add origin https://github.com/schmic75-gasos/UpperOffice.git

# 6️⃣ Přidat všechny soubory a commitnout
git add .
git commit -m "Version 1.0.2 clean copy for GitHub"

# 7️⃣ Pushnout na GitHub (force, pokud je historie jiná)
git push --force origin main
