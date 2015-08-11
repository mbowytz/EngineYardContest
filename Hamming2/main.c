#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <float.h>

  char words[1000][25];
  
char * randomString(long salt, char* mystring) {
     char randChar[2]="";
     int counter = 0;
     srand((unsigned)time(NULL)+salt+salt);
     int M = 33;
     int N = 126;
      for (counter = 0; counter < 5; counter++)
      {          
          sprintf(randChar,"%c",M + rand() / ( RAND_MAX / ( N - M ) + 1 ));
          strcat(mystring, randChar);
      }
      return(mystring);
}       
char * randomWords(int wordcount, long salt, char* output) {

     int i,random_num;
     srand((unsigned)time(NULL)+salt);
       
  for (i = 0; i < 12; i++) {
      random_num = rand() / ( RAND_MAX / wordcount + 1 );
      strcat(output,words[random_num]);
      strcat(output," ");      
   }    
   /*strcat(output,randomString(salt,mystring));*/
   return(output);
}

/**************BEGIN*****************/
/* sha1.c : Implementation of the Secure Hash Algorithm */

/* SHA: NIST's Secure Hash Algorithm */

/*	This version written November 2000 by David Ireland of 
	DI Management Services Pty Limited <code@di-mgt.com.au>

	Adapted from code in the Python Cryptography Toolkit, 
	version 1.0.0 by A.M. Kuchling 1995.
*/

/* AM Kuchling's posting:- 
   Based on SHA code originally posted to sci.crypt by Peter Gutmann
   in message <30ajo5$oe8@ccu2.auckland.ac.nz>.
   Modified to test for endianness on creation of SHA objects by AMK.
   Also, the original specification of SHA was found to have a weakness
   by NSA/NIST.  This code implements the fixed version of SHA.
*/

/* Here's the first paragraph of Peter Gutmann's posting:
   
The following is my SHA (FIPS 180) code updated to allow use of the "fixed"
SHA, thanks to Jim Gillogly and an anonymous contributor for the information on
what's changed in the new version.  The fix is a simple change which involves
adding a single rotate in the initial expansion function.  It is unknown
whether this is an optimal solution to the problem which was discovered in the
SHA or whether it's simply a bandaid which fixes the problem with a minimum of
effort (for example the reengineering of a great many Capstone chips).
*/

/* h files included here to make this just one file ... */

/* global.h */

#ifndef _GLOBAL_H_
#define _GLOBAL_H_ 1

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* BYTE defines a unsigned character */
typedef unsigned char BYTE;

#ifndef TRUE
  #define FALSE	0
  #define TRUE	( !FALSE )
#endif /* TRUE */

#endif /* end _GLOBAL_H_ */

/* sha.h */

#ifndef _SHA_H_
#define _SHA_H_ 1

/* #include "global.h" */

/* The structure for storing SHS info */

typedef struct 
{
	UINT4 digest[ 5 ];            /* Message digest */
	UINT4 countLo, countHi;       /* 64-bit bit count */
	UINT4 data[ 16 ];             /* SHS data buffer */
	int Endianness;
} SHA_CTX;

/* Message digest functions */

void SHAInit(SHA_CTX *);
void SHAUpdate(SHA_CTX *, BYTE *buffer, int count);
void SHAFinal(BYTE *output, SHA_CTX *);

#endif /* end _SHA_H_ */

/* endian.h */

#ifndef _ENDIAN_H_
#define _ENDIAN_H_ 1

void endianTest(int *endianness);

#endif /* end _ENDIAN_H_ */

/* sha.c */

#include <stdio.h>
#include <string.h>

static void SHAtoByte(BYTE *output, UINT4 *input, unsigned int len);

/* The SHS block size and message digest sizes, in bytes */

#define SHS_DATASIZE    64
#define SHS_DIGESTSIZE  20


/* The SHS f()-functions.  The f1 and f3 functions can be optimized to
   save one boolean operation each - thanks to Rich Schroeppel,
   rcs@cs.arizona.edu for discovering this */

/*#define f1(x,y,z) ( ( x & y ) | ( ~x & z ) )          // Rounds  0-19 */
#define f1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )           /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                       /* Rounds 20-39 */
/*#define f3(x,y,z) ( ( x & y ) | ( x & z ) | ( y & z ) )   // Rounds 40-59 */
#define f3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )   /* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )                       /* Rounds 60-79 */

/* The SHS Mysterious Constants */

#define K1  0x5A827999L                                 /* Rounds  0-19 */
#define K2  0x6ED9EBA1L                                 /* Rounds 20-39 */
#define K3  0x8F1BBCDCL                                 /* Rounds 40-59 */
#define K4  0xCA62C1D6L                                 /* Rounds 60-79 */

/* SHS initial values */

#define h0init  0x67452301L
#define h1init  0xEFCDAB89L
#define h2init  0x98BADCFEL
#define h3init  0x10325476L
#define h4init  0xC3D2E1F0L

/* Note that it may be necessary to add parentheses to these macros if they
   are to be called with expressions as arguments */
/* 32-bit rotate left - kludged with shifts */

#define ROTL(n,X)  ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

/* The initial expanding function.  The hash function is defined over an
   80-UINT2 expanded input array W, where the first 16 are copies of the input
   data, and the remaining 64 are defined by

        W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]

   This implementation generates these values on the fly in a circular
   buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
   optimization.

   The updated SHS changes the expanding function by adding a rotate of 1
   bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
   for this information */

#define expand(W,i) ( W[ i & 15 ] = ROTL( 1, ( W[ i & 15 ] ^ W[ (i - 14) & 15 ] ^ \
                                                 W[ (i - 8) & 15 ] ^ W[ (i - 3) & 15 ] ) ) )


/* The prototype SHS sub-round.  The fundamental sub-round is:

        a' = e + ROTL( 5, a ) + f( b, c, d ) + k + data;
        b' = a;
        c' = ROTL( 30, b );
        d' = c;
        e' = d;

   but this is implemented by unrolling the loop 5 times and renaming the
   variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
   This code is then replicated 20 times for each of the 4 functions, using
   the next 20 values from the W[] array each time */

#define subRound(a, b, c, d, e, f, k, data) \
    ( e += ROTL( 5, a ) + f( b, c, d ) + k + data, b = ROTL( 30, b ) )

/* Initialize the SHS values */

void SHAInit(SHA_CTX *shsInfo)
{
    endianTest(&shsInfo->Endianness);
    /* Set the h-vars to their initial values */
    shsInfo->digest[ 0 ] = h0init;
    shsInfo->digest[ 1 ] = h1init;
    shsInfo->digest[ 2 ] = h2init;
    shsInfo->digest[ 3 ] = h3init;
    shsInfo->digest[ 4 ] = h4init;

    /* Initialise bit count */
    shsInfo->countLo = shsInfo->countHi = 0;
}


/* Perform the SHS transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers due to the complexity of the expressions
   and the size of the basic block.  It may be necessary to split it into
   sections, e.g. based on the four subrounds

   Note that this corrupts the shsInfo->data area */

static void SHSTransform( digest, data )
     UINT4 *digest, *data ;
    {
    UINT4 A, B, C, D, E;     /* Local vars */
    UINT4 eData[ 16 ];       /* Expanded data */

    /* Set up first buffer and local data buffer */
    A = digest[ 0 ];
    B = digest[ 1 ];
    C = digest[ 2 ];
    D = digest[ 3 ];
    E = digest[ 4 ];
    memcpy( (POINTER)eData, (POINTER)data, SHS_DATASIZE );

    /* Heavy mangling, in 4 sub-rounds of 20 interations each. */
    subRound( A, B, C, D, E, f1, K1, eData[  0 ] );
    subRound( E, A, B, C, D, f1, K1, eData[  1 ] );
    subRound( D, E, A, B, C, f1, K1, eData[  2 ] );
    subRound( C, D, E, A, B, f1, K1, eData[  3 ] );
    subRound( B, C, D, E, A, f1, K1, eData[  4 ] );
    subRound( A, B, C, D, E, f1, K1, eData[  5 ] );
    subRound( E, A, B, C, D, f1, K1, eData[  6 ] );
    subRound( D, E, A, B, C, f1, K1, eData[  7 ] );
    subRound( C, D, E, A, B, f1, K1, eData[  8 ] );
    subRound( B, C, D, E, A, f1, K1, eData[  9 ] );
    subRound( A, B, C, D, E, f1, K1, eData[ 10 ] );
    subRound( E, A, B, C, D, f1, K1, eData[ 11 ] );
    subRound( D, E, A, B, C, f1, K1, eData[ 12 ] );
    subRound( C, D, E, A, B, f1, K1, eData[ 13 ] );
    subRound( B, C, D, E, A, f1, K1, eData[ 14 ] );
    subRound( A, B, C, D, E, f1, K1, eData[ 15 ] );
    subRound( E, A, B, C, D, f1, K1, expand( eData, 16 ) );
    subRound( D, E, A, B, C, f1, K1, expand( eData, 17 ) );
    subRound( C, D, E, A, B, f1, K1, expand( eData, 18 ) );
    subRound( B, C, D, E, A, f1, K1, expand( eData, 19 ) );

    subRound( A, B, C, D, E, f2, K2, expand( eData, 20 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 21 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 22 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 23 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 24 ) );
    subRound( A, B, C, D, E, f2, K2, expand( eData, 25 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 26 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 27 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 28 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 29 ) );
    subRound( A, B, C, D, E, f2, K2, expand( eData, 30 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 31 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 32 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 33 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 34 ) );
    subRound( A, B, C, D, E, f2, K2, expand( eData, 35 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 36 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 37 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 38 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 39 ) );

    subRound( A, B, C, D, E, f3, K3, expand( eData, 40 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 41 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 42 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 43 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 44 ) );
    subRound( A, B, C, D, E, f3, K3, expand( eData, 45 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 46 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 47 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 48 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 49 ) );
    subRound( A, B, C, D, E, f3, K3, expand( eData, 50 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 51 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 52 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 53 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 54 ) );
    subRound( A, B, C, D, E, f3, K3, expand( eData, 55 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 56 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 57 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 58 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 59 ) );

    subRound( A, B, C, D, E, f4, K4, expand( eData, 60 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 61 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 62 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 63 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 64 ) );
    subRound( A, B, C, D, E, f4, K4, expand( eData, 65 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 66 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 67 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 68 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 69 ) );
    subRound( A, B, C, D, E, f4, K4, expand( eData, 70 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 71 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 72 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 73 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 74 ) );
    subRound( A, B, C, D, E, f4, K4, expand( eData, 75 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 76 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 77 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 78 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 79 ) );

    /* Build message digest */
    digest[ 0 ] += A;
    digest[ 1 ] += B;
    digest[ 2 ] += C;
    digest[ 3 ] += D;
    digest[ 4 ] += E;
    }

/* When run on a little-endian CPU we need to perform byte reversal on an
   array of long words. */

static void longReverse(UINT4 *buffer, int byteCount, int Endianness )
{
    UINT4 value;

    if (Endianness==TRUE) return;
    byteCount /= sizeof( UINT4 );
    while( byteCount-- )
        {
        value = *buffer;
        value = ( ( value & 0xFF00FF00L ) >> 8  ) | \
                ( ( value & 0x00FF00FFL ) << 8 );
        *buffer++ = ( value << 16 ) | ( value >> 16 );
        }
}

/* Update SHS for a block of data */

void SHAUpdate(SHA_CTX *shsInfo, BYTE *buffer, int count)
{
    UINT4 tmp;
    int dataCount;

    /* Update bitcount */
    tmp = shsInfo->countLo;
    if ( ( shsInfo->countLo = tmp + ( ( UINT4 ) count << 3 ) ) < tmp )
        shsInfo->countHi++;             /* Carry from low to high */
    shsInfo->countHi += count >> 29;

    /* Get count of bytes already in data */
    dataCount = ( int ) ( tmp >> 3 ) & 0x3F;

    /* Handle any leading odd-sized chunks */
    if( dataCount )
        {
        BYTE *p = ( BYTE * ) shsInfo->data + dataCount;

        dataCount = SHS_DATASIZE - dataCount;
        if( count < dataCount )
            {
            memcpy( p, buffer, count );
            return;
            }
        memcpy( p, buffer, dataCount );
        longReverse( shsInfo->data, SHS_DATASIZE, shsInfo->Endianness);
        SHSTransform( shsInfo->digest, shsInfo->data );
        buffer += dataCount;
        count -= dataCount;
        }

    /* Process data in SHS_DATASIZE chunks */
    while( count >= SHS_DATASIZE )
        {
        memcpy( (POINTER)shsInfo->data, (POINTER)buffer, SHS_DATASIZE );
        longReverse( shsInfo->data, SHS_DATASIZE, shsInfo->Endianness );
        SHSTransform( shsInfo->digest, shsInfo->data );
        buffer += SHS_DATASIZE;
        count -= SHS_DATASIZE;
        }

    /* Handle any remaining bytes of data. */
    memcpy( (POINTER)shsInfo->data, (POINTER)buffer, count );
    }

/* Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void SHAFinal(BYTE *output, SHA_CTX *shsInfo)
{
    int count;
    BYTE *dataPtr;

    /* Compute number of bytes mod 64 */
    count = ( int ) shsInfo->countLo;
    count = ( count >> 3 ) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    dataPtr = ( BYTE * ) shsInfo->data + count;
    *dataPtr++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = SHS_DATASIZE - 1 - count;

    /* Pad out to 56 mod 64 */
    if( count < 8 )
        {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset( dataPtr, 0, count );
        longReverse( shsInfo->data, SHS_DATASIZE, shsInfo->Endianness );
        SHSTransform( shsInfo->digest, shsInfo->data );

        /* Now fill the next block with 56 bytes */
        memset( (POINTER)shsInfo->data, 0, SHS_DATASIZE - 8 );
        }
    else
        /* Pad block to 56 bytes */
        memset( dataPtr, 0, count - 8 );

    /* Append length in bits and transform */
    shsInfo->data[ 14 ] = shsInfo->countHi;
    shsInfo->data[ 15 ] = shsInfo->countLo;

    longReverse( shsInfo->data, SHS_DATASIZE - 8, shsInfo->Endianness );
    SHSTransform( shsInfo->digest, shsInfo->data );

	/* Output to an array of bytes */
	SHAtoByte(output, shsInfo->digest, SHS_DIGESTSIZE);

	/* Zeroise sensitive stuff */
	memset((POINTER)shsInfo, 0, sizeof(shsInfo));
}

static void SHAtoByte(BYTE *output, UINT4 *input, unsigned int len)
{	/* Output SHA digest in byte array */
	unsigned int i, j;

	for(i = 0, j = 0; j < len; i++, j += 4) 
	{
        output[j+3] = (BYTE)( input[i]        & 0xff);
        output[j+2] = (BYTE)((input[i] >> 8 ) & 0xff);
        output[j+1] = (BYTE)((input[i] >> 16) & 0xff);
        output[j  ] = (BYTE)((input[i] >> 24) & 0xff);
	}
}

void endianTest(int *endian_ness)
{
	if((*(unsigned short *) ("#S") >> 8) == '#')
	{
		/* printf("Big endian = no change\n"); */
		*endian_ness = !(0);
	}
	else
	{
		/* printf("Little endian = swap\n"); */
		*endian_ness = 0;
	}
}

/***************END******************/

int MinInt(int a, int b)
{
  if (a < b)
    return a;
  else
    return b;
}
int MaxInt(int a, int b)
{
  if (a < b)
    return b;
  else
    return a;
}

int hex2bin(char *hex, char *bin)
{
        register int i = 0, j = 0;
        int hex_len;
        
        hex_len = strlen(hex);
        /*
        if(hex_len == 0 || !hex)
                return -1;
                */
        if(hex_len > 2 && hex[0] == '0' && hex[1] == 'x')
                i = 2;

        for( ; i < hex_len; i++, j += 4) {
                switch(tolower(hex[i])) {
                        case '0': memmove(&bin[j], "0000", 4); break;
                        case '1': memmove(&bin[j], "0001", 4); break;
                        case '2': memmove(&bin[j], "0010", 4); break;
                        case '3': memmove(&bin[j], "0011", 4); break;
                        case '4': memmove(&bin[j], "0100", 4); break;
                        case '5': memmove(&bin[j], "0101", 4); break;
                        case '6': memmove(&bin[j], "0110", 4); break;
                        case '7': memmove(&bin[j], "0111", 4); break;
                        case '8': memmove(&bin[j], "1000", 4); break;
                        case '9': memmove(&bin[j], "1001", 4); break;
                        case 'a': memmove(&bin[j], "1010", 4); break;
                        case 'b': memmove(&bin[j], "1011", 4); break;
                        case 'c': memmove(&bin[j], "1100", 4); break;
                        case 'd': memmove(&bin[j], "1101", 4); break;
                        case 'e': memmove(&bin[j], "1110", 4); break;
                        case 'f': memmove(&bin[j], "1111", 4); break;
                        default:
                                return -1;      /*  invalid hex digit */
                }
        }
        return 0;
}

int HammingDistanceStrings(char * str_1, char * str_2)
{
  int char_i, length, count;
  /*
  // if the strings differ in length we automatically have a hamming
  // distance > 0; so add that to count right away and then we can
  // stop comparing strings when the shortest string is exhausted
  */
  length = MinInt(strlen(str_1), strlen(str_2));
  count = 0;
  count = count + (abs(strlen(str_1) - strlen(str_2)));

  for (char_i = 0; char_i < length; char_i++)
  {
    if (str_1[char_i] != str_2[char_i])
      count++;
  }

  return count;
}
int printHelp() {
    
    printf("Usage: hamming.exe -t target SHA-1 digest value\n");
    
}

    unsigned char digest[40];
	
int main(int argc, char *argv[])
{
  char a[1500] = "";
  char b[1500] = "";  
  char tmp[1500] = "";
  char target[41] = "";  
  char arg[10] = "";
  char randomWordString[200] = "";
  unsigned char message[100];
  unsigned char message_with_random[106];
  char mystring[6];
  char c[20];  /* declare a char array */
  FILE *file;  /* declare a FILE pointer  */
  int wordcount, i, random_num, lowest_distance = 999;
  time_t start, end;
  double diff;
  long j,k,l;
  char t[3]="";
  SHA_CTX sha;

  if (argc > 1) {

		i = 1;
		while (i < argc) {
			strcpy(arg, argv[i]);
			if (strcmp(arg, "-t") == 0 || strcmp(arg, "--target") == 0 || strcmp(arg, "-T") == 0) {
                i++;
				if (strlen(argv[i]) != 40) {
                  printf("ERROR: Target SHA-1 digest must be 40 chars in length\nYours was %d characters long.\n",strlen(argv[i]));
                  return 0;
                }
                else {
                  strcpy(target,argv[i]);
                  i++;
                  continue;
                }
			} else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
				printHelp();
				return 0;
			} else {
				printf ("Unknown option given: \"%s\".\n", arg);
				printHelp();
				return 0;
			}
		}
	} 
    else  {
          printHelp();
          return 0;
    }

  start = time(NULL);
  wordcount = 0;
  file = fopen("wordlist.txt", "r"); 
  /* open a text file for reading */
  if(file==NULL) {
    printf("Error: can't open file.\n");
    /* fclose(file); DON'T PASS A NULL POINTER TO fclose !! */
    return 1;
  }
  else {
    
    while(fgets(c, 20, file)!=NULL) { 
      /* keep looping until NULL pointer... */
      
      c[strlen(c) -1] =  '\0'; /* trim off the newline char */
      
      sprintf(words[wordcount],"%s",c);
      wordcount++;
      /* print the file one line at a time  */
    }
    wordcount--;
    printf("\nWordCount:%d\nNow closing file...\n",wordcount);
    fclose(file);
  }

    /* This is our target */
    i = hex2bin(target, b); /*"6cac827bae250971a8b1fb6e2a96676f7a077b60", b);*/

 j = 0; 

  while(lowest_distance > 0) {   
    
    
      strcpy(randomWordString,"");     
      strcpy(mystring,"");
      strcpy(message_with_random,"");

      strcpy(message,randomWords(wordcount,j,randomWordString));
      
      for(k = 0; k < 50; k++) {
      strcpy(mystring,"");
      strcpy(message_with_random,message);
      /*
      srand((unsigned)time(NULL)+k);
      */
      for (l = 0; l < strlen(message_with_random); l++) {                    
        if(rand() / ( RAND_MAX / 2 )==1) message_with_random[l]=toupper(message_with_random[l]);
      }
      strcat(message_with_random,randomString(j+k,mystring)); /*add the random string to the end*/
      
	  SHAInit(&sha);
	  SHAUpdate(&sha, message_with_random, strlen(message_with_random));
	  SHAFinal(digest, &sha);
    
      strcpy(tmp,"");
    
      for (i = 0; i < 20; i++)        
  	  {
        snprintf(t, 2, "%02x", digest[i]);
        strcat(tmp,t);        
	  }

      i = hex2bin(tmp,a);
      i = HammingDistanceStrings(a,b);
    
      if (i < lowest_distance) { 
        printf("Msg:%s\nSHA:%s\n",message_with_random,tmp);
        printf("Hamming Distance:%i\n\n",i);
        lowest_distance = i;
      }
    }
    
    j++;
    if (j % 50000 == 0){

        end = time(NULL);        
        diff = difftime(end, start);
        
        printf("\n=============================\nSeconds Elapsed:%f\n",diff);
        printf("Calcs Per Second:%f\n",j/diff);
        start = time(NULL);
        j = 0;
     }
        
  }
  
  system("PAUSE"); 
  return 0;
}
