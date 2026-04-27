#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<'USAGE'
Usage:
  ./gobfuscate.sh -in <input.go> [-out <output.go>] [-seed <number>]

Options:
  -in    Fichier Go d'entrée (obligatoire)
  -out   Fichier Go de sortie (défaut: <input>_obf.go)
  -seed  Seed optionnelle pour une obfuscation reproductible
  -h     Affiche cette aide

Exemples:
  ./gobfuscate.sh -in demo.go
  ./gobfuscate.sh -in demo.go -out demo_obf.go
  ./gobfuscate.sh -in demo.go -seed 123
USAGE
}

IN_FILE=""
OUT_FILE=""
SEED=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -in)
      IN_FILE="${2:-}"
      shift 2
      ;;
    -out)
      OUT_FILE="${2:-}"
      shift 2
      ;;
    -seed)
      SEED="${2:-}"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Option inconnue: $1" >&2
      show_help
      exit 2
      ;;
  esac
done

if [[ -z "$IN_FILE" ]]; then
  echo "Erreur: -in est obligatoire." >&2
  show_help
  exit 2
fi

if [[ ! -f "$IN_FILE" ]]; then
  echo "Erreur: fichier d'entrée introuvable: $IN_FILE" >&2
  exit 1
fi

if [[ -z "$OUT_FILE" ]]; then
  base="${IN_FILE%.go}"
  if [[ "$base" == "$IN_FILE" ]]; then
    OUT_FILE="${IN_FILE}_obf.go"
  else
    OUT_FILE="${base}_obf.go"
  fi
fi

cmd=(go run gobfuscate.go -in "$IN_FILE" -out "$OUT_FILE")
if [[ -n "$SEED" ]]; then
  cmd+=( -seed "$SEED" )
fi

"${cmd[@]}"

echo "✅ Obfuscation terminée"
echo "   Entrée : $IN_FILE"
echo "   Sortie : $OUT_FILE"
if [[ -n "$SEED" ]]; then
  echo "   Seed   : $SEED"
else
  echo "   Seed   : aléatoire"
fi
