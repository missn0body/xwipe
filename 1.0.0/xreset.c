// To CitricDolphin1, with love, from anson

// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// OpenSSL libraries
#include <openssl/evp.h>
#include <openssl/hmac.h>

/////////////////////////////////////////////////////////////////////////////////////
// Definitions
/////////////////////////////////////////////////////////////////////////////////////

static constexpr short bufsize = 256;
static constexpr short keysize = 16;
static constexpr unsigned char keyconst[] =
{
	0xBC, 0x20, 0x05, 0x1A,
	0xB5, 0x97, 0xF9, 0x60,
	0x48, 0x37, 0x5A, 0x83,
	0x78, 0x7F, 0xE5, 0x94
};

static const char *VERSION = "1.0.0";
static const char *buttonmap = "AXYUDLR";

/////////////////////////////////////////////////////////////////////////////////////
// Helper functions
/////////////////////////////////////////////////////////////////////////////////////

// This assumes that the input and output arrays are the same size
bool digest_HDD_HMAC(unsigned char *input, unsigned char *output, unsigned int size)
{
	if(input == nullptr || output == nullptr || size <= 0) return nullptr;
	return HMAC(EVP_sha1(), keyconst, keysize, input, size, output, &size) != nullptr;
}

void usage(void) { printf("usage!\n"); }

void version(void) { printf("version!\n"); }

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
	unsigned char HDDinput[bufsize] = {0}, result[bufsize] = {0};

	// Argument parsing here
	int c;
	while(--argc > 0 && (*++argv)[0] != '\0')
	{
		// I didn't want to use another header for isdigit(), so this ugly thing
		// will have to do
		if((*argv)[0] != '-' && ((**argv - '0') >= 1 || (**argv - '0') <= 9))
		{
			if(HDDinput[0] != '\0')
			{
				fprintf(stderr, "%s: discarded program input -- \"%s\"\n", program, *argv);
				continue;
			}

			snprintf((char *)HDDinput, bufsize, "%s", *argv);
		}

		if((*argv)[0] == '-')
		{
			// If there's another dash, then it's a long option.
			// Move the pointer up 2 places and compare the word itself.
			if((*argv)[1] == '-')
			{
				// Using continue statements here so that the user
				// can use both single character and long options
				// simultaniously, and the loop can test both.
				if(strcmp((*argv) + 2, "help")    == 0) { usage();   exit(EXIT_SUCCESS); }
				if(strcmp((*argv) + 2, "version") == 0) { version(); exit(EXIT_SUCCESS); }
			}
			while((c = *++argv[0]))
			{
				// Single character option testing here.
				switch(c)
				{
					case 'h': usage(); exit(EXIT_SUCCESS);
					// This error flag can either be set by a
					// completely unrelated character inputted,
					// or you managed to put -option instead of
					// --option.
					default : fprintf(stderr, "%s: unknown option -- \"%s\", try \"--help\"\n", program, *argv);
						  exit(EXIT_FAILURE);
				}
			}

			continue;
		}
	}

	// Check if we've had the important data
	if(HDDinput[0] == '\0')
	{
		fprintf(stderr, "%s: no HDD input given\n", program);
		exit(EXIT_FAILURE);
	}

	// Getting the HMAC-SHA1 digest of the HDD key
	if(!digest_HDD_HMAC(HDDinput, result, bufsize))
	{
		fprintf(stderr, "%s: error while generating HMAC digest\n", program);
		exit(EXIT_FAILURE);
	}

	// Printing the result for debugging purposes
	for(unsigned int i = 0; i < bufsize && result[i] != 0; i++)
	{
		printf("0x%02X ", result[i]); // or just "%02X" if you are not using C11 or later
	}

	putchar('\n');
	exit(EXIT_SUCCESS);
}
