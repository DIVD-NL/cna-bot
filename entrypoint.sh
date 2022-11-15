#!/bin/sh 
#  args:
#    - ${{ inputs.path }}
#    - ${{ inputs.publish }}
#    - ${{ inputs.ignore }}
#    - ${{ inputs.min-reserved }}
#    - ${{ inputs.reserve }}
#    - ${{ inputs.pr }}

# Fail if we encounter an error
set -e

# Process command line arguments
if [[ "$3" != "" ]]; then
	SKIP="--skip $3"
fi
if [[ "$4" != "" ]]; then
	RESERVED="--min-reserved $4"
fi
if [[ "$5" != "" ]]; then
	RESERVE="--reserve $5"
fi

if [[ "$6" == "true" ]]; then
	UPDATE_LOCAL="--update-local"
fi

# Check if we have CVE Services credentials
if [[ "$CVE_USER" = "" || "$CVE_ORG" == "" || "$CVE_API_KEY" = "" || "$CVE_ENVIRONMENT" == "" ]] ; then
	echo "Authentication variables for cvelib are not set."
	exit 1
fi

# Need to declare this directory safe, to get git commit time
git config --global --add safe.directory $PWD

# Check the CVE records
echo "*** Checking CVE records ***"
/run/cve_check.py --path $1 $SKIP $RESERVED $RESERVE --schema /run/cve50.json

if [[ "$2" == "true" ]]; then
	echo "*** Publishing/updating CVE records ***"
	/run/cve_publish_update.py --path $1 $UPDATE_LOCAL

	if [[ "$6" == "true" ]]; then
		# Require github_token
		if [[ -z "${GITHUB_TOKEN}" ]]; then
		  MESSAGE='Missing input "github_token: ${{ secrets.GITHUB_TOKEN }}".'
		  echo -e "[ERROR] ${MESSAGE}"
		  exit 1
		fi
		if [[ -z "${GITHUB_BRANCH}" ]]; then
		  MESSAGE='Missing input "github_branch: ".'
		  echo -e "[ERROR] ${MESSAGE}"
		  exit 1
		fi

		echo -e "\nSetting GitHub credentials..."
		# Prevents issues with: fatal: unsafe repository ('/github/workspace' is owned by someone else)
		git config --global --add safe.directory "${GITHUB_WORKSPACE}"
		git config --global --add safe.directory /github/workspace
		git remote set-url origin "https://${GITHUB_ACTOR}:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}"
		git config --global user.name "${GITHUB_ACTOR}"
		git config --global user.email "${GITHUB_ACTOR}@users.noreply.github.com"
		# Needed for hub binary
		export GITHUB_USER="${GITHUB_ACTOR}"

		if [[ $( git status $1 | grep "working tree clean" ) -gt 1 ]]; then
			echo "Nothing to commit, cowardly bailing out"
		else
			# Build branch / pr
			echo -e "\nUpdating all branches..."
			git fetch origin '+refs/heads/*:refs/heads/*' --update-head-ok

			COUNT=$( git branch | grep "$GITHUB_BRANCH" | wc -l )
			if [[ $( git branch | grep "$GITHUB_BRANCH" | wc -l ) -gt 0 ]] ;  then
				git checkout $GITHUB_BRANCH
				git pull
			else
				git checkout -b $GITHUB_BRANCH
			fi

			echo "Creating pull request..."
			git reset # Unstage the rest
			git add $1
			git commit -m "Updating records to match remote records"
			git push --set-upstream origin $GITHUB_BRANCH
			DEFAULT_BRANCH=$( git remote show origin | sed -n '/HEAD branch/s/.*: //p' )
			gh pr create --title "$GITHUB_PR_DESC" --body "Autmatic PR by https://github.com/DIVD-NL/cve-rsus-validate-submit"
		fi
	fi
fi
