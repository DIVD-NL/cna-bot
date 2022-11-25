#!/bin/sh 
#  env:
#    CVE_USER :              ${{ inputs.cve-user }}
#    CVE_ORG :               ${{ inputs.cve-org }}
#    CVE_API_KEY :           ${{ inputs.cve-api-key }}
#    CVE_ENVIRONMENT :       ${{ inputs.cve-environment }}
#    GITHUB_TOKEN :          ${{ inputs.github-token }}
#    GITHUB_BRANCH :         ${{ inputs.github-branch }}
#    GITHUB_PR_DESC :        ${{ inputs.github-pr-description }}
#    CVE_PATH :              ${{ inputs.path }}
#    CVE_PUBLISH :           ${{ inputs.publish }}
#    IGNORE_CHECKS :         ${{ inputs.ignore }}
#    MIN_RESERVED :          ${{ inputs.min-reserved }}
#    RESERVE :     		     ${{ inputs.reserve }}
#    DO_PR :                 ${{ inputs.pr }}
#    INCLUDE_RESERVATIONS :  ${{ inputs.check-reservations }}
#    RESERVATIONS-PATH :     ${{ inputs.reservations-path }}

# Fail if we encounter an error
set -e
set -x

# Process env variables
if [[ $( echo $CVE_PATH | egrep "^\/" | wc -l ) -gt 0 ]] ; then
	echo "CVE_PATH should be a relative path, '$CVE_PATH' isn't, bailing out..."
	exit 1
fi

if [[ ! -d $CVE_PATH ]]; then
	echo "CVE_PATH '$CVE_PATH' is not a directory, bailing out..."
	exit 1
fi

if [[ "$IGNORE_CHECKS" != "" ]]; then
	IGNORE_CHECKS="--skip $IGNORE_CHECKS"
fi
if [[ "$MIN_RESERVED" != "" ]]; then
	MIN_RESERVED="--min-reserved $MIN_RESERVED"
fi
if [[ "$RESERVE" != "" ]]; then
	RESERVE="--reserve $RESERVE"
fi

if [[ "$DO_PR" == "true" ]]; then
	UPDATE_LOCAL="--update-local"
fi

if [[ -z "$RESERVATIONS_PATH" ]]; then
	RESERVATIONS_PATH="$CVE_PATH/reservations/"
fi

if [[ "$INCLUDE_RESERVATIONS" == true ]]; then
	RESERVATIONS_TOO="--include-reservations"
	DO_RESERVATIONS="--reservations-path $RESERVATIONS_PATH"
fi

if [[ $INCLUDE_RESERVATIONS == "true" && ! -d $RESERVATIONS_PATH ]]; then
	mkdir $RESERVATIONS_PATH
fi
if [[ $( echo $RESERVATIONS_PATH | egrep "^\/" | wc -l ) -gt 0 ]] ; then
	echo "RESERVATIONS_PATH should be a relative path, '$RESERVATIONS_PATH' isn't, bailing out..."
	exit 1
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
rm -f /tmp/cve_check.log
CMD="/run/cve_check.py --path $CVE_PATH $IGNORE_CHECKS $MIN_RESERVED $RESERVE $RESERVATIONS_TOO $DO_RESERVATIONS --schema /run/cve50.json --log /tmp/cve_check.log"
echo "Running: $CMD"
$CMD || echo "Check failed!"

if [[ $( cat /tmp/cve_check.log | wc -l ) -gt 0 ]] ; then
	if [[ ! -z "${GITHUB_TOKEN}" ]]; then
		(
			echo CNA-Bot detected errors in your PR:
			echo
			cat /tmp/cve_check.log
		) | gh pr comment review -r -F -
	fi
	exit 1
fi


if [[ "$CVE_PUBLISH" == "true" ]]; then
	echo
	echo "*** Publishing/updating CVE records ***"
	CMD="/run/cve_publish_update.py --path $CVE_PATH $UPDATE_LOCAL $RESERVATIONS_TOO $DO_RESERVATIONS"
	echo "Running: $CMD"
	$CMD

	if [[ "$DO_PR" == "true" ]]; then
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
		git config --global user.name "${GITHUB_ACTOR}"
		git config --global user.email "${GITHUB_ACTOR}@users.noreply.github.com"
		# Needed for hub binary
		export GITHUB_USER="${GITHUB_ACTOR}"

		if [[ $( git status | grep "working tree clean" | wc -l ) -gt 0 ]]; then
			echo "Nothing to commit, cowardly bailing out"
			exit 0
		else
			# Build branch / pr
			git clone "https://${GITHUB_ACTOR}:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}" new_repo
			cd new_repo

			echo -e "\nUpdating all branches..."
			git fetch origin '+refs/heads/*:refs/heads/*' --update-head-ok
			if [[ $( git branch | grep "$GITHUB_BRANCH" | wc -l ) -gt 0 ]] ;  then
				git checkout $GITHUB_BRANCH
				git pull origin $GITHUB_BRANCH
			else
				git checkout -b $GITHUB_BRANCH
			fi

			# Copy updated directories
			cp -r ../$CVE_PATH/* $CVE_PATH/
			if [[ "$INCLUDE_RESERVATIONS" ]] ; then
				if [[ $( ls $RESERVATIONS_PATH | wc -l  ) -gt 0 ]]; then
					cp -r ../$RESERVATIONS_PATH/* $RESERVATIONS_PATH
				fi
			fi

			if [[ $( git status | grep "working tree clean" | wc -l ) -gt 0 ]]; then
				echo "Nothing to commit, cowardly bailing out"
				exit 0
			fi
			echo -e "\nCommiting changes to branch and creating pull request..."

			# Add CVE records
			git add $CVE_PATH
			# Unstage reservations if they happend to be in $CVE_PATH
			git restore --staged $RESERVATIONS_PATH

			# Add reservations
			if [[ "$INCLUDE_RESERVATIONS" ]] ; then
				git add $RESERVATIONS_PATH
			fi

			if [[ "$INCLUDE_RESERVATIONS" ]] ; then
				git commit -m "Updating records to match remote records and reservations"
			else
				git commit -m "Updating records to match remote records"
			fi
			git push --set-upstream origin $GITHUB_BRANCH
			if [[ $( gh pr view $GITHUB_BRANCH | grep "no pull requests found" | wc -l ) -gt 0 ]]; then
				echo "A pull request for $GITHUB_BRANCH already exists"
			else
				gh pr create --title "$GITHUB_PR_DESC" --body "Autmatic PR by https://github.com/DIVD-NL/cve-rsus-validate-submit"
			fi
			cd ..
			rm -rf new_repo
		fi
	fi
fi
