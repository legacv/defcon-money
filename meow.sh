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

        # cleanup if no official WP dl
        if wget -q -P $1 $dl 2>/dev/null ; then
                :
        else
                printf "[*] no DL for $1 - cleaning up...\n"
                rm -rf $1
                return
        fi

        # unzip a bitch
        echo "[*] unzipping $1..."
        unzip -q $1/$zipfile -d $1

        # scan
        echo "[*] scanning $1 with semgrep..."
        out="$1/$1-semgrep.json"
        semgrep --config=auto --quiet --json --output="$out" $1/$1

        # biiiiig jq command
        printf "[*] making a report for $1...\n"
        jq -r '["Path","Start","End","CWE","Vuln Class","Likelihood","Confidence","Impact"],(.results[] | [.path,.start.line,.end.line,(.extra.metadata.cwe | join("; ")),(.extra.metadata.vulnerability_class | join("; ")),.extra.metadata.likelihood,.extra.metadata.confidence,.extra.metadata.impact]) | @csv' $out > $1/$1-report.csv

        # TODO: check csv vulns, purge if not
}

main () {
        while IFS= read -r line || [ -n "$line" ]
        do
                trim=$(echo "$line" | sed 's:/*$::')
                init $trim
        done < "$1"
        echo "[*] done!"
}

main $1
