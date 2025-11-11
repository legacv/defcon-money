# to scrape a plugin's name, details (install count) from wp plugins site
# then grab its file (if not exists, check plugins.svn)
# then unzip it into a folder, run semgrep analysis and create a document on likely vulnerabilities
# doesn't include robust error handling or check if you have the tools installed because this is for my machine lol
# run at your own risk

# c legacv 2025
# MIT license

init () {
        # grab basic info and make README
        echo "[*] getting info for $1..."
        url="https://wordpress.org/plugins/$1/"
        mkdir $1
        version=$(curl --silent $url | grep "softwareVersion" | cut -d '"' -f 4)
        installs=$(curl --silent $url | grep "Active installations" | cut -d ">" -f 2 | cut -d "<" -f 1)
        printf "Name: $line\nVersion: $version\nInstalls: $installs\n" > $1/README.txt

        # download ZIP
        echo "[*] downloading $1..."
        dl=$(curl --silent $url | grep 'href="https://downloads.wordpress.org' | cut -d '"' -f 6)
        zipfile=$(curl --silent $url | grep 'href="https://downloads.wordpress.org' | cut -d '/' -f 5 | cut -d '"' -f 1)
        # TODO: add an error check here to make sure $dl is a real URL
        wget -q -P $1 $dl

        # unzip a bitch
        echo "[*] unzipping $1..."
        unzip -q $1/$zipfile -d $1

        # scan
        echo "[*] scanning $1 with semgrep..."
        semgrep --config=auto --quiet --json --output="$1/$1-semgrep.json" $1/$1

        # TODO: json filtering, severity table w/ jq
}

main () {
        while IFS= read -r line || [ -n "$line" ]
        do
                init $line
        done < "$1"
        echo "[*] done!"
}

main $1
