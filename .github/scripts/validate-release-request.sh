#!/usr/bin/env bash
set -euo pipefail

for name in PUBLISH_RELEASE SIGNPATH_TEST SIGNPATH_RELEASE_DRY_RUN; do
  case "${!name-}" in
    true|false) ;;
    *) echo "::error::$name must be a boolean"; exit 2 ;;
  esac
done

if [[ $PUBLISH_RELEASE == true && ( $SIGNPATH_TEST == true || $SIGNPATH_RELEASE_DRY_RUN == true ) ||
      $SIGNPATH_TEST == true && $SIGNPATH_RELEASE_DRY_RUN == true ]]; then
  echo "::error::publish_release, signpath_test, and signpath_release_dry_run are mutually exclusive"
  exit 2
fi

if [[ $PUBLISH_RELEASE == true || $SIGNPATH_TEST == true || $SIGNPATH_RELEASE_DRY_RUN == true ]] &&
   [[ ${SOURCE_EVENT-} != workflow_dispatch || ${SOURCE_REF-} != refs/heads/main ]]; then
  echo "::error::Signing or publication requires a main-branch workflow dispatch"
  exit 2
fi
