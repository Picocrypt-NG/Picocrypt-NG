#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset GIT_DIR
for name in appimageupdate zsync2 libappimage cpr args; do
  mkdir -p "/source/$name"
  tar -xzf "inputs/$name.tar.gz" --strip-components=1 -C "/source/$name"
done
patch --batch --forward --fuzz=0 -p1 -d /source/appimageupdate < inputs/nul-terminate-mkdtemp-template.patch
cmake -S /source/appimageupdate -B /compiled -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_QT_UI=OFF -DBUILD_TESTING=OFF -DBUILD_LIBAPPIMAGEUPDATE_ONLY=OFF \
  -DLIBAPPIMAGE_SHARED_ONLY=ON -DCPR_FORCE_USE_SYSTEM_CURL=ON \
  -DCPR_BUILD_TESTS=OFF -DCPR_BUILD_TESTS_SSL=OFF -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DFETCHCONTENT_SOURCE_DIR_ZSYNC2=/source/zsync2 -DFETCHCONTENT_SOURCE_DIR_LIBAPPIMAGE=/source/libappimage \
  -DFETCHCONTENT_SOURCE_DIR_CPR=/source/cpr -DFETCHCONTENT_SOURCE_DIR_ARGS=/source/args \
  -DCMAKE_EXPORT_PACKAGE_REGISTRY=OFF -DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF
cmake --build /compiled --target validate --parallel 2
mkdir -p /runtime/{usr/local/bin,usr/bin,etc,tmp,input,var/lib/dpkg,usr/share/doc/appimage-verifier}
install -m 0755 /compiled/src/validate/validate /runtime/usr/local/bin/validate
printf 'nonroot:x:65532:65532:Verifier:/tmp:/sbin/nologin\n' > /runtime/etc/passwd
printf 'nonroot:x:65532:\n' > /runtime/etc/group
chmod 1777 /runtime/tmp
cp /etc/os-release /runtime/etc/os-release
cp /etc/lsb-release /runtime/etc/lsb-release
programs=(/compiled/src/validate/validate /usr/bin/gpg /usr/bin/gpgconf /usr/bin/gpg-agent /usr/bin/gpg-connect-agent)
for program in "${programs[@]:1}"; do install -m 0755 "$program" "/runtime$program"; done
for program in "${programs[@]}"; do ldd "$program"; done > /build/linked-libraries.txt
awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' /build/linked-libraries.txt | sort -u > /build/libraries.txt
: > /build/package-owners.txt
mapfile -t libraries < /build/libraries.txt
for file in "${programs[@]:1}" "${libraries[@]}"; do
  if ! dpkg-query -S "$(readlink -f "$file")" >> /build/package-owners.txt 2>/dev/null; then
    dpkg-query -S "$file" >> /build/package-owners.txt
  fi
done
while IFS= read -r library; do
  mkdir -p "/runtime$(dirname "$library")"
  cp -L "$library" "/runtime$library"
done < /build/libraries.txt
awk -F ': /' '{print $1}' /build/package-owners.txt | sort -u > /build/packages.txt
while IFS= read -r package; do
  dpkg-query -s "$package" >> /runtime/var/lib/dpkg/status
  printf '\n' >> /runtime/var/lib/dpkg/status
  package=${package%%:*}
  if [[ -f /usr/share/doc/$package/copyright ]]; then
    mkdir -p "/runtime/usr/share/doc/$package"
    cp -L "/usr/share/doc/$package/copyright" "/runtime/usr/share/doc/$package/copyright"
  fi
done < /build/packages.txt
cp manifest.json sources.lock.json os-packages.lock.json inputs/nul-terminate-mkdtemp-template.patch /runtime/usr/share/doc/appimage-verifier/
for name in appimageupdate zsync2 libappimage cpr args; do
  for file in LICENSE LICENSE.txt COPYING; do
    if [[ -f /source/$name/$file ]]; then cp "/source/$name/$file" "/runtime/usr/share/doc/appimage-verifier/$name-$file"; fi
  done
done
find /runtime -type d -exec chmod a+rx {} +
find /runtime -type f -exec chmod a+r {} +
for file in /runtime/lib64/ld-linux*; do chmod a+rx "$file"; done
