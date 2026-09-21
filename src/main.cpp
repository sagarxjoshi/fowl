#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <vector>
#include <iomanip>
#include <openssl\evp.h>


/* type aliases */
typedef unsigned int uint;
typedef unsigned char uchar;

/* supported crypto algorithms */
const std::vector<std::string> digestTypes = { "sha256", "md5", "sha512"};

/* calculate file size */
uint calculateSize(std::string file) {

	// input stream with cursor set at end of file
	std::ifstream pfile;
	pfile.open(file, std::ios::binary | std::ios::ate);

	if (!pfile) {

		std::cout << "Unable to open the file" << std::endl;
		return 1;
	}

	// end of file position captured as size
	std::streamsize size = pfile.tellg();

	pfile.close();

	return size;
	
}

/* Evaluate file type */
void checkType(std::string file) {

	// string var for magic bytes
	std::string mbytes;
	std::map<std::string, std::string> extensions = { 
		{"MZ", "executable"}, 
		{"%PDF", "PDF document"}, 
		{"PK", "Office Doc\\Compressed archive"},
		{"ELF", "ELF binary"}
	};
	std::fstream pfile(file);

	if (!pfile) {

		std::cout << "Unable to open the file" << std::endl;
		exit(-1);
	}

	// extracting initial bytes of data from file, stops at first white character
	pfile >> mbytes;

	pfile.close();

	for (auto ext : extensions) {

		if (mbytes.find(ext.first) != std::string::npos) {

			std::cout << "File Type: " << ext.second << std::endl;
			break;

		}

	}

	
}


/* evaluates hash for a given file */
void calcDigest(std::string file, std::string digest) {
	
	/* digest context */
	EVP_MD_CTX *mdctx;

	/* digest name */
	const EVP_MD *md;

	/* vector to store digest value */
	uchar mdValue[EVP_MAX_MD_SIZE];

	/* unsigned integer var storing digest length */
	unsigned int md_len;

	/* store digest name */
	md = EVP_get_digestbyname(digest.c_str());

	/* create new context for digest */
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {

		std::cerr << "Message digest creation failed." << std::endl;
		exit(-1);
	}

	/* Initialize the digest */
	if (!(EVP_DigestInit_ex2(mdctx, md, NULL))) {

		std::cerr << "Failed to initialize digest." << std::endl;
		EVP_MD_CTX_free(mdctx);
	}

	/* read input file and update digest */
	std::fstream pfile(file, std::ios::in | std::ios::ate | std::ios::binary);

	// calculate the file size
	std::streamsize fileSize = pfile.tellg();

	// move to the start of file
	pfile.seekg(0, std::ios::beg);

	// create a buffer with length of file size
	std::vector<char> buffer(fileSize);

	if (pfile.read(buffer.data(), fileSize)) {

		if (!EVP_DigestUpdate(mdctx, buffer.data(), fileSize)) {
			
			std::cerr << "Message digest update failed." << std::endl;
			EVP_MD_CTX_free(mdctx);
			exit(-1);
		}

	}
	else {
		
		std::cerr << "Could not read file." << std::endl;
		exit(-1);
	}

	/* finalize digest */
	if (!EVP_DigestFinal_ex(mdctx, &mdValue[0], &md_len)) {

		std::cerr << "finalizing digest failed." << std::endl;
		EVP_MD_CTX_free(mdctx);
		exit(-1);
	}
	EVP_MD_CTX_free(mdctx);

	std::cout << digest << ": ";
	for (int i = 0; i < md_len; i++) {

		std::cout << std::setfill('0') << 
		std::setw(2) << std::hex << (int)mdValue[i];
		
	}
	std::cout << std::endl;
}


/* prints program options */
void programUsage(std::string progName) {

	std::cout << "Program options: \n" <<
		progName << " <arguments> \n" <<
		"standard use: " << progName << " <filename> \n"
		"evaluating file hash(md5 or SHA256): "  << progName << " <filename> <digest>\n" <<
		progName  << " -h or --help | Help menu" << std::endl;
}

int main(int argc, char *argv[]) {
	

	/* terminate if program called with no args */
	if (argc < 2) {

		std::cerr << "Error: Missing required arguments.\n" <<
		"For help: " << argv[0] << " -h or --help" << std::endl;
		return -1;
	}
	else {

		/* help menu */
		if ((std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {

			programUsage(argv[0]);
			return 0;

		}
		else {

			/* File type and size */
			std::string fileName = argv[1];
			std::cout << "File Size: " << calculateSize(fileName) << " bytes" << std::endl;
			checkType(fileName);
			std::cout << std::endl;
		
			/* check if valid cypto function is provided by user input */
			if (((argc > 2) && (std::count(digestTypes.begin(), digestTypes.end(), argv[2])) == false)) {

				std::cout << "Invalid cryptographic algorithm. Refer help menu.";
				return -1;


			}
			else {

				/* enum digest */
				std::string digestType = argv[2];
				calcDigest(fileName, digestType.c_str());
			}
		}
		
	}

}