#!/bin/sh
set -eu

REPO="${REPO:-/repo}"
OUT="$REPO/pki/out"
INV="$REPO/devices/inventory.json"
CNF="$REPO/pki/openssl.cnf"
INT="$OUT/intermediate"
ROOTD="$OUT/root"
export PKI_INT_DIR="$INT"
SITES="ubs escola centro horta abrigo"
ORG="Rede Vila Aurora"
export SAN="DNS:localhost"

site_of() {
  jq -r --arg id "$1" 'to_entries[] | select(any(.value[]; .id == $id)) | .key' "$INV"
}

devices_of() {
  jq -r --arg s "$1" '.[$s][].id' "$INV"
}

init_ca() {
  if [ -f "$INT/intermediate.crt" ]; then
    echo "CA já existe: $INT/intermediate.crt"
    return
  fi
  mkdir -p "$ROOTD" "$INT/newcerts" "$INT/csr"
  : > "$INT/index.txt"
  echo "unique_subject = no" > "$INT/index.txt.attr"
  echo 1000 > "$INT/serial"
  echo 1000 > "$INT/crlnumber"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$ROOTD/root.key"
  openssl req -x509 -new -key "$ROOTD/root.key" -sha384 -days 3650 \
    -subj "/O=$ORG/CN=Vila Aurora Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$ROOTD/root.crt"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$INT/intermediate.key"
  openssl req -new -key "$INT/intermediate.key" \
    -subj "/O=$ORG/CN=Vila Aurora Issuing CA" -out "$INT/csr/intermediate.csr"
  openssl x509 -req -in "$INT/csr/intermediate.csr" \
    -CA "$ROOTD/root.crt" -CAkey "$ROOTD/root.key" -CAserial "$ROOTD/root.srl" -CAcreateserial \
    -days 1825 -sha384 -extfile "$CNF" -extensions v3_intermediate \
    -out "$INT/intermediate.crt"

  cat "$INT/intermediate.crt" "$ROOTD/root.crt" > "$OUT/ca-chain.crt"
  echo "CA raiz (P-384, 10 anos) e intermediária (P-256, 5 anos) criadas"
}

issue() {
  cn="$1"; ou="$2"; ext="$3"; days="$4"; dir="$5"
  mkdir -p "$dir"
  if [ -f "$dir/$cn.crt" ]; then
    echo "  já existe: $cn"
    return
  fi
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$cn.key" 2>/dev/null
  openssl req -new -key "$dir/$cn.key" -subj "/O=$ORG/OU=$ou/CN=$cn" -out "$INT/csr/$cn.csr"
  openssl ca -batch -config "$CNF" -extensions "$ext" -days "$days" -notext \
    -in "$INT/csr/$cn.csr" -out "$dir/$cn.crt" 2>/dev/null
  cp "$OUT/ca-chain.crt" "$dir/ca-chain.crt"
  echo "  emitido: $cn ($ext, $days dias)"
}

gen_acl() {
  site="$1"
  dest="$OUT/sites/$site/broker/acl"
  {
    echo "user monitor"
    echo "topic read vila/#"
    echo "topic write vila/+/sim/cenario"
    echo
    echo "user $site-agent"
    echo "topic read vila/$site/#"
    echo "topic write vila/$site/+/comando"
    echo "topic write vila/$site/agent/#"
    echo
    for id in $(devices_of "$site"); do
      echo "user $id"
      for t in telemetria estado evento; do
        echo "topic write vila/$site/$id/$t"
      done
      echo "topic read vila/$site/$id/comando"
      echo "topic read vila/$site/sim/cenario"
      echo
    done
  } > "$dest"
}

gen_crl() {
  openssl ca -config "$CNF" -gencrl -out "$OUT/crl.pem" 2>/dev/null
  for site in $SITES; do
    mkdir -p "$OUT/sites/$site/broker"
    cp "$OUT/crl.pem" "$OUT/sites/$site/broker/crl.pem"
  done
  echo "CRL publicada ($(grep -c . "$INT/index.txt" | tr -d ' ') certificados no registro, $(grep -c '^R' "$INT/index.txt" || true) revogados)"
}

setup() {
  init_ca
  for site in $SITES; do
    echo "[$site]"
    export SAN="DNS:broker,DNS:$site-broker,DNS:localhost"
    issue "$site-broker" "$site" server_cert 365 "$OUT/sites/$site/broker"
    if [ -f "$OUT/sites/$site/broker/$site-broker.crt" ]; then
      cp "$OUT/sites/$site/broker/$site-broker.crt" "$OUT/sites/$site/broker/broker.crt"
      cp "$OUT/sites/$site/broker/$site-broker.key" "$OUT/sites/$site/broker/broker.key"
    fi
    export SAN="DNS:localhost"
    for id in $(devices_of "$site"); do
      issue "$id" "$site" device_cert 90 "$OUT/sites/$site/devices"
    done
    issue "$site-agent" "$site" device_cert 90 "$OUT/sites/$site/agent"
    gen_acl "$site"
  done
  echo "[hub]"
  export SAN="DNS:hub-ingest,IP:10.99.0.1"
  issue hub-ingest hub server_cert 365 "$OUT/hub/ingest"
  export SAN="DNS:localhost"
  echo "[operação]"
  issue monitor operacao device_cert 90 "$OUT/monitor"
  gen_crl
}

cert_path() {
  id="$1"
  if [ "$id" = "monitor" ]; then
    echo "$OUT/monitor/monitor.crt"
  elif [ "$id" = "hub-ingest" ]; then
    echo "$OUT/hub/ingest/hub-ingest.crt"
  elif [ "${id%-agent}" != "$id" ]; then
    echo "$OUT/sites/${id%-agent}/agent/$id.crt"
  else
    echo "$OUT/sites/$(site_of "$id")/devices/$id.crt"
  fi
}

revoke() {
  id="$1"; reason="${2:-keyCompromise}"
  crt="$(cert_path "$id")"
  [ -f "$crt" ] || { echo "Certificado não encontrado: $id"; exit 1; }
  openssl ca -config "$CNF" -revoke "$crt" -crl_reason "$reason" 2>&1 | grep -v "^Using configuration" || true
  echo "Revogado: $id (motivo: $reason)"
  gen_crl
  echo "--- verificação do certificado revogado contra a cadeia e a CRL"
  openssl verify -crl_check -CAfile "$OUT/ca-chain.crt" -CRLfile "$OUT/crl.pem" "$crt" 2>&1 || true
}

rotate() {
  id="$1"
  site="$(site_of "$id")"
  [ -n "$site" ] || { echo "Dispositivo não está no inventário: $id"; exit 1; }
  dir="$OUT/sites/$site/devices"
  if openssl verify -crl_check -CAfile "$OUT/ca-chain.crt" -CRLfile "$OUT/crl.pem" "$dir/$id.crt" >/dev/null 2>&1; then
    openssl ca -config "$CNF" -revoke "$dir/$id.crt" -crl_reason superseded 2>/dev/null || true
    echo "Certificado antigo de $id revogado (motivo: superseded)"
  fi
  stamp="$(date +%Y%m%dT%H%M%S)"
  mv "$dir/$id.crt" "$dir/$id.crt.substituido-$stamp"
  mv "$dir/$id.key" "$dir/$id.key.substituido-$stamp"
  issue "$id" "$site" device_cert 90 "$dir"
  gen_crl
}

status() {
  echo "STATUS    EXPIRA EM   REVOGADO EM  SERIAL  TITULAR"
  awk -F'\t' '
    function d(v) { return (v == "") ? "-" : "20" substr(v,1,2) "-" substr(v,3,2) "-" substr(v,5,2) }
    {
      st = ($1 == "V") ? "válido" : ($1 == "R") ? "REVOGADO" : $1;
      split($3, r, ",");
      printf "%-9s %-11s %-12s %-7s %s\n", st, d($2), d(r[1]), $4, $6
    }' "$INT/index.txt"
}

intruso() {
  site="$1"
  alvo="$(devices_of "$site" | head -n1)"
  dir="$OUT/intruso"
  mkdir -p "$dir"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/ca-falsa.key" 2>/dev/null
  openssl req -x509 -new -key "$dir/ca-falsa.key" -days 30 \
    -subj "/O=$ORG/CN=Vila Aurora Root CA" -out "$dir/ca-falsa.crt" 2>/dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$alvo.key" 2>/dev/null
  openssl req -new -key "$dir/$alvo.key" -subj "/O=$ORG/OU=$site/CN=$alvo" -out "$dir/$alvo.csr" 2>/dev/null
  openssl x509 -req -in "$dir/$alvo.csr" -CA "$dir/ca-falsa.crt" -CAkey "$dir/ca-falsa.key" \
    -CAcreateserial -days 30 -out "$dir/$alvo.crt" 2>/dev/null
  echo "Certificado forjado para '$alvo' (assinado por uma CA falsa com o mesmo nome da nossa raiz)"
  echo "$alvo"
}

show() {
  crt="$(cert_path "$1")"
  openssl x509 -in "$crt" -noout -subject -issuer -serial -dates -ext keyUsage,extendedKeyUsage
  echo "--- verificação da cadeia e da CRL"
  openssl verify -crl_check -CAfile "$OUT/ca-chain.crt" -CRLfile "$OUT/crl.pem" "$crt" 2>&1 || true
}

cmd="${1:-}"
shift || true
case "$cmd" in
  setup)   setup ;;
  revoke)  revoke "$@" ;;
  rotate)  rotate "$@" ;;
  status)  status ;;
  intruso) intruso "$@" ;;
  show)    show "$@" ;;
  *) echo "uso: pki.sh setup|revoke <id>|rotate <id>|status|intruso <site>|show <id>"; exit 1 ;;
esac
