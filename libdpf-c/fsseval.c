#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "block.h"

block dpf_reverse_lsb(block input){
	static long long b1 = 0;
	static long long b2 = 1;
	block xor = dpf_make_block(b1, b2);
	return dpf_xor(input, xor);
}

block dpf_set_lsb_zero(block input){
	int lsb = dpf_lsb(input);

	if(lsb == 1){
		return dpf_reverse_lsb(input);	
	}else{
		return input;
	}
}

void PRG(AES_KEY *key, block input, block* output1, block* output2, int* bit1, int* bit2){
	input = dpf_set_lsb_zero(input);

	block stash[2];
	stash[0] = input;
	stash[1] = dpf_reverse_lsb(input);

	AES_ecb_encrypt_blks(stash, 2, key);

	stash[0] = dpf_xor(stash[0], input);
	stash[1] = dpf_xor(stash[1], input);
	stash[1] = dpf_reverse_lsb(stash[1]);

	*bit1 = dpf_lsb(stash[0]);
	*bit2 = dpf_lsb(stash[1]);

	*output1 = dpf_set_lsb_zero(stash[0]);
	*output2 = dpf_set_lsb_zero(stash[1]);
}

static int getbit(int x, int n, int b){
	return ((unsigned int)(x) >> (n - b)) & 1;
}

void GEN(AES_KEY *key, int alpha, int n, unsigned char** k0, unsigned char **k1){
	int maxlayer = n - 7;
	//int maxlayer = n;

	block s[maxlayer + 1][2];
	int t[maxlayer + 1 ][2];
	block sCW[maxlayer];
	int tCW[maxlayer][2];

	s[0][0] = dpf_random_block();
	s[0][1] = dpf_random_block();
	t[0][0] = dpf_lsb(s[0][0]);
	t[0][1] = t[0][0] ^ 1;
	s[0][0] = dpf_set_lsb_zero(s[0][0]);
	s[0][1] = dpf_set_lsb_zero(s[0][1]);

	int i;
	block s0[2], s1[2]; // 0=L,1=R
	#define LEFT 0
	#define RIGHT 1
	int t0[2], t1[2];
	for(i = 1; i<= maxlayer; i++){
		PRG(key, s[i-1][0], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
		PRG(key, s[i-1][1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);

		int keep, lose;
		int alphabit = getbit(alpha, n, i);
		if(alphabit == 0){
			keep = LEFT;
			lose = RIGHT;
		}else{
			keep = RIGHT;
			lose = LEFT;
		}

		sCW[i-1] = dpf_xor(s0[lose], s1[lose]);

		tCW[i-1][LEFT] = t0[LEFT] ^ t1[LEFT] ^ alphabit ^ 1;
		tCW[i-1][RIGHT] = t0[RIGHT] ^ t1[RIGHT] ^ alphabit;

		if(t[i-1][0] == 1){
			s[i][0] = dpf_xor(s0[keep], sCW[i-1]);
			t[i][0] = t0[keep] ^ tCW[i-1][keep];
		}else{
			s[i][0] = s0[keep];
			t[i][0] = t0[keep];
		}

		if(t[i-1][1] == 1){
			s[i][1] = dpf_xor(s1[keep], sCW[i-1]);
			t[i][1] = t1[keep] ^ tCW[i-1][keep];
		}else{
			s[i][1] = s1[keep];
			t[i][1] = t1[keep];
		}
	}

	block finalblock;
	finalblock = dpf_zero_block();
	finalblock = dpf_reverse_lsb(finalblock);

	char shift = (alpha) & 127;
	if(shift & 64){
		finalblock = dpf_left_shirt(finalblock, 64);
	}
	if(shift & 32){
		finalblock = dpf_left_shirt(finalblock, 32);
	}
	if(shift & 16){
		finalblock = dpf_left_shirt(finalblock, 16);
	}
	if(shift & 8){
		finalblock = dpf_left_shirt(finalblock, 8);
	}
	if(shift & 4){
		finalblock = dpf_left_shirt(finalblock, 4);
	}
	if(shift & 2){
		finalblock = dpf_left_shirt(finalblock, 2);
	}
	if(shift & 1){
		finalblock = dpf_left_shirt(finalblock, 1);
	}
	dpf_cb(finalblock);
	finalblock = dpf_reverse_lsb(finalblock);

	finalblock = dpf_xor(finalblock, s[maxlayer][0]);
	finalblock = dpf_xor(finalblock, s[maxlayer][1]);

	unsigned char *buff0;
	unsigned char *buff1;
	buff0 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer + 16);
	buff1 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer + 16);

	if(buff0 == NULL || buff1 == NULL){
		printf("Memory allocation failed\n");
		exit(1);
	}

	buff0[0] = n;
	memcpy(&buff0[1], &s[0][0], 16);
	buff0[17] = t[0][0];
	for(i = 1; i <= maxlayer; i++){
		memcpy(&buff0[18 * i], &sCW[i-1], 16);
		buff0[18 * i + 16] = tCW[i-1][0];
		buff0[18 * i + 17] = tCW[i-1][1]; 
	}
	memcpy(&buff0[18 * maxlayer + 18], &finalblock, 16); 

	buff1[0] = n;
	memcpy(&buff1[18], &buff0[18], 18 * (maxlayer));
	memcpy(&buff1[1], &s[0][1], 16);
	buff1[17] = t[0][1];
	memcpy(&buff1[18 * maxlayer + 18], &finalblock, 16);

	*k0 = buff0;
	*k1 = buff1;
} 

block EVAL(AES_KEY *key, unsigned char* k, int x){
	int n = k[0];
	int maxlayer = n - 7;

	block s[maxlayer + 1];
	int t[maxlayer + 1];
	block sCW[maxlayer];
	int tCW[maxlayer][2];
	block finalblock;

	memcpy(&s[0], &k[1], 16);
	t[0] = k[17];

	int i;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&finalblock, &k[18 * (maxlayer + 1)], 16);

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		PRG(key, s[i - 1], &sL, &sR, &tL, &tR); 

		if(t[i-1] == 1){
			sL = dpf_xor(sL, sCW[i-1]);
			sR = dpf_xor(sR, sCW[i-1]);
			tL = tL ^ tCW[i-1][0];
			tR = tR ^ tCW[i-1][1];	
		}

		int xbit = getbit(x, n, i);
		if(xbit == 0){
			s[i] = sL;
			t[i] = tL;
		}else{
			s[i] = sR;
			t[i] = tR;
		}
	}

	block res;
	res = s[maxlayer];
	if(t[maxlayer] == 1){
		res = dpf_reverse_lsb(res);
	}

	if(t[maxlayer] == 1){
		res = dpf_xor(res, finalblock);
	}

	return res;
}

block* EVALFULL(AES_KEY *key, unsigned char* k){
	int n = k[0];
	int maxlayer = n - 7;
	int maxlayeritem = 1 << (n - 7);

	block s[2][maxlayeritem];
	int t[2][maxlayeritem];

	int curlayer = 1;

	block sCW[maxlayer];
	int tCW[maxlayer][2];
	block finalblock;

	memcpy(&s[0][0], &k[1], 16);
	t[0][0] = k[17];

	int i, j;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&finalblock, &k[18 * (maxlayer + 1)], 16);

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		int itemnumber = 1 << (i - 1);
		for(j = 0; j < itemnumber; j++){
			PRG(key, s[1 - curlayer][j], &sL, &sR, &tL, &tR); 

			if(t[1 - curlayer][j] == 1){
				sL = dpf_xor(sL, sCW[i-1]);
				sR = dpf_xor(sR, sCW[i-1]);
				tL = tL ^ tCW[i-1][0];
				tR = tR ^ tCW[i-1][1];	
			}

			s[curlayer][2 * j] = sL;
			t[curlayer][2 * j] = tL;
			s[curlayer][2 * j + 1] = sR; 
			t[curlayer][2 * j + 1] = tR;
		}
		curlayer = 1 - curlayer;
	}

	int itemnumber = 1 << maxlayer;
	block *res = (block*) malloc(sizeof(block) * itemnumber);

	for(j = 0; j < itemnumber; j ++){
		res[j] = s[1 - curlayer][j];

		if(t[1 - curlayer][j] == 1){
			res[j] = dpf_reverse_lsb(res[j]);
		}

		if(t[1 - curlayer][j] == 1){
			res[j] = dpf_xor(res[j], finalblock);
		}
	}

	return res;
}

block* EVALPARTIAL(AES_KEY *key, unsigned char* k, int numpoints){
	int n = k[0];
	int maxlayer = n - 7;
	int fulldomain = 1 << (n - 7);

	// Number of leaf blocks needed: ceil(numpoints / 128)
	int numblocks = (numpoints + 127) / 128;
	if(numblocks > fulldomain) numblocks = fulldomain;

	if(numblocks == 0) return NULL;

	// If requesting full domain, delegate to EVALFULL
	if(numblocks == fulldomain){
		return EVALFULL(key, k);
	}

	int bufsize = numblocks + 1;

	block *s0 = (block*) calloc(bufsize, sizeof(block));
	block *s1 = (block*) calloc(bufsize, sizeof(block));
	int *t0 = (int*) calloc(bufsize, sizeof(int));
	int *t1 = (int*) calloc(bufsize, sizeof(int));

	int curlayer = 1;

	block sCW[maxlayer];
	int tCW[maxlayer][2];
	block finalblock;

	// Use s0/s1 as ping-pong: curlayer=1 means write to s1/t1, read from s0/t0
	memcpy(&s0[0], &k[1], 16);
	t0[0] = k[17];

	int i, j;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&finalblock, &k[18 * (maxlayer + 1)], 16);

	block *scur, *sprev;
	int *tcur, *tprev;

	// Set up initial pointers: layer 0 data is in s0/t0
	// curlayer=1 means we write to s1/t1, read from s0/t0
	scur = s1; tcur = t1;
	sprev = s0; tprev = t0;

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		// Number of parents to expand: ceil(numblocks / 2^(maxlayer - i + 1))
		int shift = maxlayer - i + 1;
		int parents = (numblocks + (1 << shift) - 1) >> shift;

		for(j = 0; j < parents; j++){
			PRG(key, sprev[j], &sL, &sR, &tL, &tR);

			if(tprev[j] == 1){
				sL = dpf_xor(sL, sCW[i-1]);
				sR = dpf_xor(sR, sCW[i-1]);
				tL = tL ^ tCW[i-1][0];
				tR = tR ^ tCW[i-1][1];
			}

			scur[2 * j] = sL;
			tcur[2 * j] = tL;
			scur[2 * j + 1] = sR;
			tcur[2 * j + 1] = tR;
		}

		// Swap pointers
		block *stmp = scur; scur = sprev; sprev = stmp;
		int *ttmp = tcur; tcur = tprev; tprev = ttmp;
	}

	// Results are in sprev/tprev (last written layer)
	block *res = (block*) malloc(sizeof(block) * numblocks);

	for(j = 0; j < numblocks; j++){
		res[j] = sprev[j];

		if(tprev[j] == 1){
			res[j] = dpf_reverse_lsb(res[j]);
		}

		if(tprev[j] == 1){
			res[j] = dpf_xor(res[j], finalblock);
		}
	}

	free(s0);
	free(s1);
	free(t0);
	free(t1);

	return res;
}

int getsize(int n){
	int maxlayer = n - 7;

	return (18 * (maxlayer + 1) + 16);
}


int main(int argc, char** argv){
	long long userkey1 = 597349; long long userkey2 = 121379; 
	block userkey = dpf_make_block(userkey1, userkey2);

	dpf_seed(NULL);

	AES_KEY key;
	AES_set_encrypt_key(userkey, &key);

	if(argc != 3){
		printf("format: fsseval N filename\n");
		exit(0);
	}

	int n;
	char filename[1001];
	sscanf(argv[1], "%d", &n);
	sscanf(argv[2], "%s", filename);

	unsigned char *k = (unsigned char*) malloc(getsize(n));

	if(k == NULL){
		printf("Failed to allocate a memory space.\n");
		exit(0);
	}

	FILE *fp = fopen(filename, "rb");

	if(fp == NULL){
		printf("Failed to open the file.\n");
		exit(0);
	}

	fread(k, getsize(n), 1, fp);
	fclose(fp);

	block *resf;
	resf = EVALFULL(&key, k);

	int j;
	int totalblocknumber = (1 << n) / 128;
	for(j = 0; j < totalblocknumber; j++){
		dpf_cbnotnewline(resf[j]);
	}

	return 0;
}
