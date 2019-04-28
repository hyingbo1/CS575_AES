#include <iostream>
#include <bitset>
#include <string>
#include <fstream>
#include <random>
#include <cstdlib>
#include <cstdio>
#include <errno.h>
#include <fstream>
#include <sstream>
#include <string.h>
#include <iostream>
#include <assert.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iomanip>
#include <sys/time.h>
#include <sys/resource.h>

#include <omp.h>
using namespace std;

#define GET_BIT(x,p)  ((1<<p)&x)>>p


int mode;
int g_aes_key_bits[] = {
    /* AES_CYPHER_128 */ 128,
    /* AES_CYPHER_192 */ 192,
    /* AES_CYPHER_256 */ 256,
};

int Nr[] = {
    /* AES_CYPHER_128 */  10,
    /* AES_CYPHER_192 */  12,
    /* AES_CYPHER_256 */  14,
};

int Nk[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  6,
    /* AES_CYPHER_256 */  8,
};

uint8_t S_Box[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 
     0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 
     0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
     0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 
     0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 
     0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 
     0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 
     0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
     0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 
     0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 
     0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 
     0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 
     0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
     0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 
     0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 
     0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 
     0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

uint8_t Inv_S_Box[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 
     0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 
     0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 
     0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 
     0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 
     0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 
     0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 
     0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 
     0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 
     0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 
     0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 
     0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 
     0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 
     0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 
     0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 
     0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 
     0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};


// Rcon
uint32_t Rcon[15] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 
		 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
                 0x6c000000, 0xd8000000, 0xab000000, 0xed000000, 0x9a000000
                 };



void invert_plain(uint8_t in[4*4]){
    for(int i=0;i<3;i++){
        for(int j=i+1;j<4;j++){
            uint8_t temp = in[4*i+j];
            in[4*i+j] = in[4*j+i];
            in[4*j+i] = temp;
        }
        
    }
}
/**
 *  Sub
 */
void SubBytes(uint8_t mtx[4*4])
{
    for(int i=0; i<16; ++i)
    {
	int row = (GET_BIT(mtx[i],7))*8 + (GET_BIT(mtx[i],6))*4 + (GET_BIT(mtx[i],5))*2 + (GET_BIT(mtx[i],4));
	int col = (GET_BIT(mtx[i],3))*8 + (GET_BIT(mtx[i],2))*4 + (GET_BIT(mtx[i],1))*2 + (GET_BIT(mtx[i],0));
	mtx[i] = S_Box[row][col];
    }


}

/**
 *  Shift
 */
void ShiftRows(uint8_t mtx[4*4])
{
    // Second line left shift
    uint8_t temp = mtx[4];
    for(int i=0; i<3; ++i)
	mtx[i+4] = mtx[i+5];
    mtx[7] = temp;
    // Third line
    temp = mtx[8];
    mtx[8] = mtx[10];
    mtx[10] = temp;
    temp = mtx[9];
    mtx[9] = mtx[11];
    mtx[11] = temp;

    // Forth line
    temp = mtx[15];
    for(int i=3; i>0; --i)
	mtx[i+12] = mtx[i+11];
    mtx[12] = temp;


}

/**
 *  Mul in GF(2^8)
 */

uint8_t GFMul(uint8_t a, uint8_t b) { 
    uint8_t p = 0;/* the product of the multiplication */
    uint8_t hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
	if ((b & uint8_t(1)) != 0) {/* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
	    p ^= a;
	}
	hi_bit_set = (uint8_t) (a & uint8_t(0x80));/* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
	a <<= 1;
	if (hi_bit_set != 0) {
	    a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
	}
	b >>= 1;
    }
    return p;
}

/**
 *  MixCol
 */
void MixColumns(uint8_t mtx[4*4])
{
    uint8_t arr[4];
    uint8_t y[16] = { 2, 3, 1, 1,  1, 2, 3, 1,  1, 1, 2, 3,  3, 1, 1, 2};
    int i,j,r;
    //invert_plain(mtx);

    
    for(int i=0; i<4; ++i)
    {
        
	for(int j=0; j<4; ++j)
	    arr[j] = mtx[i+j*4]; // col

	mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
	mtx[i+4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
	mtx[i+8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
	mtx[i+12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
    } 

}

/**
 *  Addround
 */
void AddRoundKey(uint8_t mtx[4*4], uint32_t k[4])
{
    for(int i=0; i<4; ++i)
    {
	uint32_t k1 = k[i] >> 24;
	uint32_t k2 = (k[i] << 8) >> 24;
	uint32_t k3 = (k[i] << 16) >> 24;
	uint32_t k4 = (k[i] << 24) >> 24;
	
	mtx[i] = mtx[i] ^ uint8_t(k1);
	mtx[i+4] = mtx[i+4] ^ uint8_t(k2);
	mtx[i+8] = mtx[i+8] ^ uint8_t(k3);
	mtx[i+12] = mtx[i+12] ^ uint8_t(k4);
    }

}


/**
 *  Inv Sub
 */
void InvSubBytes(uint8_t mtx[4*4])
{
    for(int i=0; i<16; ++i)
    {
	int row = (GET_BIT(mtx[i],7))*8 + (GET_BIT(mtx[i],6))*4 + (GET_BIT(mtx[i],5))*2 + (GET_BIT(mtx[i],4));
	int col = (GET_BIT(mtx[i],3))*8 + (GET_BIT(mtx[i],2))*4 + (GET_BIT(mtx[i],1))*2 + (GET_BIT(mtx[i],0));
	mtx[i] = Inv_S_Box[row][col];
    }
}

/**
 *  
 */
void InvShiftRows(uint8_t mtx[4*4])
{
    
    uint8_t temp = mtx[7];
    for(int i=3; i>0; --i)
	mtx[i+4] = mtx[i+3];
    mtx[4] = temp;
    
    temp = mtx[8];
    mtx[8] = mtx[10];
    mtx[10] = temp;
    temp = mtx[9];
    mtx[9] = mtx[11];
    mtx[11] = temp;

    
    temp = mtx[12];
    for(int i=0; i<3; ++i)
	mtx[i+12] = mtx[i+13];
    mtx[15] = temp;
}

void InvMixColumns(uint8_t mtx[4*4])
{
    uint8_t arr[4];
    for(int i=0; i<4; ++i)
    {
	for(int j=0; j<4; ++j)
	    arr[j] = mtx[i+j*4];

	mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) 
	    ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
	mtx[i+4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) 
	    ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
	mtx[i+8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) 
	    ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
	mtx[i+12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) 
	    ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
    }
}



uint32_t Word(uint8_t& k1, uint8_t& k2, uint8_t& k3, uint8_t& k4)
{
    uint32_t result(0x00000000);
    uint32_t temp;
    temp = uint32_t(k1);  // K1
    temp <<= 24;
    result |= temp;
    temp = uint32_t(k2);  // K2
    temp <<= 16;
    result |= temp;
    temp = uint32_t(k3);  // K3
    temp <<= 8;
    result |= temp;
    temp = uint32_t(k4);  // K4
    result |= temp;
    return result;
}


uint32_t RotWord(uint32_t& rw)
{
    uint32_t high = rw << 8;
    uint32_t low = rw >> 24;
    return high | low;
}


uint32_t SubWord(uint32_t& sw)
{
    uint32_t temp = 0;
    for(int i=0; i<32; i+=8)
    {
	int row = (GET_BIT(sw,(i+7)))*8 + (GET_BIT(sw,(i+6)))*4 + (GET_BIT(sw,(i+5)))*2 + (GET_BIT(sw,(i+4)));
	int col = (GET_BIT(sw,(i+3)))*8 + (GET_BIT(sw,(i+2)))*4 + (GET_BIT(sw,(i+1)))*2 + (GET_BIT(sw,i));
	uint8_t val = S_Box[row][col];


	uint32_t temp_mask = uint32_t(val) << i;
	temp = temp | temp_mask;
    }
    return temp;
}

/**
 *  Key Exp
 */ 
void KeyExpansion(uint8_t key[], uint32_t w[])
{
    uint32_t temp;
    int i = 0;


    for(i=0;i < Nk[mode];i++) 
    {
	w[i] = Word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
    }
    

    i = Nk[mode];

    while(i < 4*(Nr[mode]+1))
    {
	temp = w[i-1]; // 记录前一个word
	if(i % Nk[mode] == 0){
            uint32_t x = RotWord(temp);
	    w[i] = w[i-Nk[mode]] ^ SubWord(x) ^ Rcon[i/Nk[mode]-1];
        }
        else if(mode==2&&(i%Nk[mode]) == 4){
            w[i] = w[i-Nk[mode]] ^ SubWord(temp);
        }
	else 
	    w[i] = w[i-Nk[mode]] ^ temp;
	++i;
    }
}

void encrypt(uint8_t in[4*4], uint32_t w[])
{
    uint32_t key[4];
    invert_plain(in);
    for(int i=0; i<4; ++i)
	key[i] = w[i];
    AddRoundKey(in, key);

    for(int round=1; round<Nr[mode]; ++round)
    {
   
	SubBytes(in);
	ShiftRows(in);
	MixColumns(in);
	for(int i=0; i<4; ++i)
	    key[i] = w[4*round+i];
	AddRoundKey(in, key);

    }

    SubBytes(in);
    ShiftRows(in);
    for(int i=0; i<4; ++i)
	key[i] = w[4*Nr[mode]+i];
    AddRoundKey(in, key);
    invert_plain(in);
}


void decrypt(uint8_t in[4*4], uint32_t w[])
{
    invert_plain(in);
    uint32_t key[4];
    for(int i=0; i<4; ++i)
	key[i] = w[4*Nr[mode]+i];
    AddRoundKey(in, key);

    for(int round=Nr[mode]-1; round>0; --round)
    {
	InvShiftRows(in);
	InvSubBytes(in);
	for(int i=0; i<4; ++i)
	    key[i] = w[4*round+i];
	AddRoundKey(in, key);
	InvMixColumns(in);
    }

    InvShiftRows(in);
    InvSubBytes(in);
    for(int i=0; i<4; ++i)
	key[i] = w[i];
    AddRoundKey(in, key);
    invert_plain(in);
}

int process_encrypt(int mode, uint8_t* p, uint32_t key[],int n_plain){
    uint8_t now_plain[16];
    ofstream fout("encryption_file",ios::binary);
    for(int i=0; i<n_plain; i++){
	for(int j=0; j<16; j++){
	    now_plain[j] = *p;
	    ++p;
	}
	encrypt(now_plain, key);
	fout.write((char*)now_plain,sizeof(uint8_t)*16);
    }
    fout.close();
    return 1;
}
int process_encrypt_parallel(int mode, uint8_t* p, uint32_t key[],int n_plain, int thread_nums=4){
    uint8_t now_plain[16];
    ofstream fout("encryption_parallel_file",ios::binary);

    for(int i=0; i<n_plain;i=i+thread_nums){
	omp_set_num_threads(thread_nums);
	uint8_t plain_box[16*thread_nums];
	#pragma omp parallel for
	for(int j=0; j<thread_nums; j++){
	    for(int k=0; k<16; k++){
		plain_box[16*j + k ] = *(p+16*j+k);
	    }
	    encrypt((plain_box+16*j), key);
	}
	
	#pragma omp barrier
	p = p+thread_nums*16;
	
	fout.write((char*)plain_box,sizeof(uint8_t)*16*thread_nums);
    }
    fout.close();
    return 1;
}
int process_decrypt(int mode, uint8_t*p, uint32_t key[], int n_plain){
    uint8_t now_plain[16];
    ofstream fout("decryption_file",ios::binary);
    for(int i=0; i<n_plain; i++){
	for(int j=0; j<16; j++){
	    now_plain[j] = *p;
	    ++p;
	}
	decrypt(now_plain, key);
	fout.write((char*)now_plain,sizeof(uint8_t)*16);
    }
    fout.close();
    return 1;
}
int process_decrypt_parallel(int mode, uint8_t* p, uint32_t key[],int n_plain, int thread_nums=4){
    uint8_t now_plain[16];
    ofstream fout("decryption_parallel_file",ios::binary);

    for(int i=0; i<n_plain;i=i+thread_nums){
	omp_set_num_threads(thread_nums);
	uint8_t plain_box[16*thread_nums];
	#pragma omp parallel for
	for(int j=0; j<thread_nums; j++){
	    for(int k=0; k<16; k++){
		plain_box[16*j + k ] = *(p+16*j+k);
	    }
	    decrypt((plain_box+16*j), key);
	}
	
	#pragma omp barrier
	p = p+thread_nums*16;
	
	fout.write((char*)plain_box,sizeof(uint8_t)*16*thread_nums);
    }
    fout.close();
    return 1;
}
int main(int argc, char** argv)
{
    /*
    uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 
		    0x04, 0x05, 0x06, 0x07,
		    0x08, 0x09, 0x0a, 0x0b,
		    0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b,
                    0x1c, 0x1d, 0x1e, 0x1f
                    };
    
    uint8_t plain[16] = {0x00, 0x11, 0x22, 0x33, 
		    0x44, 0x55, 0x66, 0x77,
		    0x88, 0x99, 0xaa, 0xbb,
		    0xcc, 0xdd, 0xee, 0xff}; 
    
    
    uint8_t key[17] = "0123456789012345";

    uint8_t plain[17]= "0123456789012345";
    
    mode = 0;
    
    char *filename = argv[1];
    
    //uint8_t plain[16] = string_to_plain(s);

    cout << "密钥是：";
    for(int i=0; i<16; ++i)
	cout << hex << key[i] << " ";
    cout << endl;

    uint32_t w[4*(Nr[mode]+1)];
    KeyExpansion(key, w);

    
    cout << endl << "plain ："<<endl;
    for(int i=0; i<16; ++i)
    {
	printf("%02x ",plain[i]);
	if((i+1)%4 == 0)
	    cout << endl;
    }
    cout << endl;


    encrypt(plain, w);
    cout << "加密后的密文："<<endl;
    for(int i=0; i<16; ++i)
    {
	//cout << hex << plain[i] << " ";
        printf("%02x ",plain[i]);
	if((i+1)%4 == 0)
	    cout << endl;
    }
    cout << endl;


    decrypt(plain, w);
    
    cout << "解密后的明文："<<endl;
    for(int i=0; i<16; ++i)
    {
	printf("%02x ",plain[i]);
	if((i+1)%4 == 0)
	    cout << endl;
    }
    cout << endl;
    */
    if(argc>3){
	mode = atoi(argv[3]);
    }
    else{
	mode = 0;
    }
    
    //uint8_t key[17] = "0123456789012345";
    uint8_t key[3][33] = {"0123456789012345","012345678901234567890123","01234567890123456789012345678901"};
    uint32_t w[4*(Nr[mode]+1)];
    KeyExpansion(key[mode], w);


    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
	int en = errno;
	std::fprintf(stderr, "Couldn't open %s: %s\n", argv[1], strerror(en));
	exit(2);
    }

    struct stat sb;
    int rv = fstat(fd, &sb); assert(rv == 0);
    // std::cout << sb.st_size << std::endl;
    // Make sure that the size is a multiple of the size of a double.
    assert(sb.st_size%sizeof(uint8_t) == 0);

    void *vp = mmap(nullptr, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (vp == MAP_FAILED) {
	int en = errno;
	fprintf(stderr, "mmap() failed: %s\n", strerror(en));
	exit(3);
    }

    rv = madvise(vp, sb.st_size, MADV_SEQUENTIAL|MADV_WILLNEED); assert(rv == 0);

    rv = close(fd); assert(rv == 0);

    uint8_t* array = (uint8_t *) vp;
    int n_plain = sb.st_size/(sizeof(uint8_t)*16);
    cout << n_plain <<endl;
    cout << argv[1];
    if(!strcmp(argv[2],"-e")){
	if(argc > 4&&!strcmp(argv[4],"-p")){
	    int thread_nums = atoi(argv[5]);
	    process_encrypt_parallel(mode,array,w,n_plain,thread_nums);
	    cout <<"encrpt parallel" << endl;
	}
	else{
	    process_encrypt(mode,array,w,n_plain);
	    cout << "encrpt" << endl;
	}
    
    }
    else if(!strcmp(argv[2],"-d")){
	if(argc > 4 && !strcmp(argv[4],"-p")){
	    int thread_nums = atoi(argv[5]);
	    process_decrypt_parallel(mode,array,w,n_plain,thread_nums);
	    cout <<"decrpt parallel" << endl;
	}
	else{
	    process_decrypt(mode,array,w,n_plain);
	    cout << "decrypt"<< endl;
	}
    }
    else{
	cout << "please enter choose -e to encypt file or -d to decrypt file" << endl; 
    }
    
    return 0;
}
