#pragma once
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <hex.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <boost/asio.hpp>
#include <array>
#include <vector>
#include "Client.h"




int main(int argc, char* argv[])
{
     
    try
    {
        Client c;
        c.start_protocol();
       
    }



    catch (std::exception& e)
    {
        std::cerr << "exception: " << e.what() << "\n";
    }
   
    return 0;
	

}
