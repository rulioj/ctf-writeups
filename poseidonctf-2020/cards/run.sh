while :; do
	ncat -l 1337 --exec ./cards
done
