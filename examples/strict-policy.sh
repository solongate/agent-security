#!/usr/bin/env sh
#
# A realistic policy, in one run — every constraint kind, both effects, permission
# scoping, and the two layers that sit beside the rules.
#
#   ./examples/strict-policy.sh
#
# WHY A SCRIPT. The interesting question about a policy is not whether one rule works;
# it is whether thirty rules of different kinds, in one document, still each decide the
# call they were written for. Typing thirty commands to find that out means most people
# test three and assume the rest.
#
# This writes a policy worth arguing with. Read it before you run it: it is deliberately
# strict, and some of these will get in your way — which is the point, because a policy
# nobody notices is one that is not enforcing anything.
#
# Run it yourself. Every command here changes a security posture, so the CLI refuses
# without a terminal and an agent cannot do this for you.

set -eu

sg() {
	printf '  %s\n' "$*"
	solongate "$@" >/dev/null
}

if ! command -v solongate >/dev/null 2>&1; then
	echo "solongate is not on PATH. Run ./install.sh first." >&2
	exit 1
fi

# One policy per machine, named `local`. Rules are appended, so running this twice is
# harmless: the store dedupes an equivalent rule rather than stacking copies.
P=local

echo
echo "Destructive shell commands"
sg policy deny $P --command 'rm -rf *'
sg policy deny $P --command 'rm -fr *'
sg policy deny $P --command '* --force*'
sg policy deny $P --command 'dd if=*'
sg policy deny $P --command 'mkfs*'
sg policy deny $P --command 'chmod -R 777*'
sg policy deny $P --command '*:(){ :|:& };:*'

echo
echo "Anything that leaves the machine"
sg policy deny $P --command 'curl *'
sg policy deny $P --command 'wget *'
sg policy deny $P --command 'nc *'
sg policy deny $P --command 'scp *'
sg policy deny $P --command 'rsync * *:*'
sg policy deny $P --command 'ssh *'

echo
echo "Publishing and deploying, which are one-way doors"
sg policy deny $P --command 'npm publish*'
sg policy deny $P --command 'pnpm publish*'
sg policy deny $P --command 'docker push*'
sg policy deny $P --command 'git push * --force*'
sg policy deny $P --command 'terraform apply*'
sg policy deny $P --command 'kubectl delete*'

echo
echo "Paths that are nobody's business"
sg policy deny $P --path '/etc/*'
sg policy deny $P --path '/var/log/*'
sg policy deny $P --path '*/.ssh/*'
sg policy deny $P --path '*/.aws/*'
sg policy deny $P --path '*/.kube/*'
sg policy deny $P --path '*/.gnupg/*'

echo
echo "Files that are secrets by their name alone"
sg policy deny $P --filename '*.pem'
sg policy deny $P --filename '*.key'
sg policy deny $P --filename '*.p12'
sg policy deny $P --filename 'id_rsa*'
sg policy deny $P --filename '.env'
sg policy deny $P --filename '.env.*'
sg policy deny $P --filename 'credentials'

echo
echo "Where a fetch may go, and where it may not"
sg policy deny $P --url 'http://*'
sg policy deny $P --url '*://*.onion/*'
sg policy allow $P --url 'https://docs.*'
sg policy allow $P --url 'https://*.github.com/*'

echo
echo "Scoped by permission — the tool class, not the argument"
# READ, WRITE, EXECUTE and NETWORK come from the TOOL NAME, so these are statements
# about which tools a rule covers. Worth knowing: Codex has no read tool and shells out
# instead, so a READ-scoped rule matches nothing there.
sg policy deny $P --path '/*' --permission WRITE
sg policy deny $P --command '*' --permission NETWORK

echo
echo "Secret detectors"
sg dlp mode block
sg dlp enable 'AWS access key'
sg dlp enable 'Private key block'
sg dlp enable 'Anthropic key'
sg dlp enable 'OpenAI key'
sg dlp enable 'GitHub token'
sg dlp enable 'Stripe key'
sg dlp enable 'JWT'
sg dlp add-custom --name internal-ticket --re 'ACME-[0-9]{6}'

echo
echo "Rate limit"
sg ratelimit set --minute 60 --hour 1000 --day 5000 --mode block

echo
echo "Activating"
sg policy activate $P

echo
echo "Done. What is enforced here:"
echo
solongate policy show $P
echo
echo "Now ask your agent to do any of it. A blocked call names the rule that stopped it."
