// To CitricDolphin1, with love, from anson

// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// OpenSSL libraries
#include <openssl/evp.h>
#include <openssl/hmac.h>

/////////////////////////////////////////////////////////////////////////////////////
// Definitions
/////////////////////////////////////////////////////////////////////////////////////

// In case of dystopian futures where char != 8 bits
typedef uint8_t u8;
static constexpr short bufsize = 256;
static constexpr short keysize = 16;
static constexpr u8 keyconst[] =
{
	0xBC, 0x20, 0x05, 0x1A,
	0xB5, 0x97, 0xF9, 0x60,
	0x48, 0x37, 0x5A, 0x83,
	0x78, 0x7F, 0xE5, 0x94
};

/////////////////////////////////////////////////////////////////////////////////////
// Helper functions
/////////////////////////////////////////////////////////////////////////////////////

// This assumes that the input and output arrays are the same size
bool digest_HDD_HMAC(u8 *input, u8 *output, unsigned int size)
{
	if(input == nullptr || output == nullptr || size <= 0) return false;
	return (HMAC(EVP_sha1(), keyconst, keysize, input, size, output, &size) == nullptr);
}

/////////////////////////////////////////////////////////////////////////////////////
// main() function
/////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	if(argc < 2 || !*argv[1])
	{
		fprintf(stderr, "%s: too few arguments, try \"--help\"\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *program = argv[0];
	u8 HDDinput[bufsize] = {0}, result[bufsize] = {0};

	// Argument parsing here
	// TODO do argument parsing so that we can test HMAC digest
	// TODO also make this a git repo

	// Check if we've had the important data
	if(HDDinput[0] == '\0')
	{
		fprintf(stderr, "%s: no HDD input given\n", program);
		exit(EXIT_FAILURE);
	}

	// Getting the HMAC-SHA1 digest of the HDD key
	bool hmac_ret = digest_HDD_HMAC(HDDinput, result, bufsize);
	if(hmac_ret == false)
	{
		fprintf(stderr, "%s: error when computing HMAC-SHA1 digest\n", program);
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
