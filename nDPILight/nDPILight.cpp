#include <ndpi_light_includes.h>
/*
 * ******** Need to revise includes *********
 */


ReaderThread reader_thread;




using namespace std;



static bool find_help(char ** begin, char ** end, const std::string& option)
//Function used to find if help is an option requested
{
    return find(begin, end, option) != end;
}

/* ********************************** */

static char * check_args(int &argc, char ** argv)
//Parsing of input args
{
    int opt;
    char * dst = nullptr;

    //In case of -h arg, print infos and terminate
    if(find_help(argv, argv + argc, "-h")) {
        cout << "nDPILight -i <file|device> \n"
             << "Usage:\n"
             << "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
             << "                            | device for live capture (comma-separated list)\n";
        return nullptr;
    }

    while((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                dst = optarg;
                break;
            default:
                cerr << "Option not valid, to check usage: " << argv[0] << " -h\n";
                return nullptr;
        }
    }

    //Device or File needed
    if(dst == nullptr) {
        cerr << "Error: no device or file specified, please check -h";
    }

    return dst;
}

/* ********************************** */

static int setup_pcap(char const * const file_or_device)
//Setup the reader_thread
{
    PcapReader reader {file_or_device};

    reader_thread.pcp_rdr = reader;
    reader_thread.

    return 0;
}

/* ********************************** */

static int setup_reader(char const * const file_or_device)
/*
 * ********** WHEN NAPATECH IS READY, NEED TO ADD THE CHECK AND SWITCH BETWEEN NAPATECH AND PCAP **********
 */
{
    /*
     * if(file_or_device != napatech) {
     *      setup_pcap();
     * }
     * else {
     *      setup_napatech();
     * }
     */

    if(setup_pcap(file_or_device) != 0) {
        return -1;
    }

    return 0;
}

/* ********************************** */

int main(int argc, char * argv[])
{
    cout << "\t-----------------------------\n"
         << "\tWELCOME TO NDPI LIGHT VERSION\n"
         << "\t-----------------------------\n\n";

//    cout << "----------------------------------\n"
//         << "nDPI version: %s\n" << ndpi_revision()
//        << " API version: %u\n" << ndpi_get_api_version()
//         << "----------------------------------\n";

    char *dst;

    if((dst = check_args(argc, argv)) == nullptr) {
        return 0;
    }


    if(setup_reader(dst) != 0) {
        cerr << "nDPILight initialization failed\n";
        return 1;
    }



    return 0;
}
