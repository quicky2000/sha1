/*
    This file is part of sha1_test
    Copyright (C) 2012  Julien Thevenon ( julien_thevenon at yahoo.fr )

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
#ifdef SHA1_SELF_TEST
#include "sha1.h"

#include <iostream>
#include <string>
#include <array>
#include <quicky_test.h>
#include <ansi_colors.h>

using namespace std;

bool check_hash( const std::string & p_string
               , const std::array<uint32_t, 5> & p_reference_key
               )
{
    bool l_ok = true;
    std::cout << R"(Check hash of ")" << p_string << R"(")" << std::endl;
    sha1 l_sha1((const uint8_t *)p_string.c_str(),8 * p_string.size());
    unsigned int l_key_index = 0;
    for(auto l_iter: p_reference_key)
    {
        l_ok &= quicky_utils::quicky_test::check_expected(l_iter, l_sha1.get_key(l_key_index), "Check key[" + std::to_string(l_key_index) +"]");
        ++l_key_index;
    }
    return l_ok;
}

int main()
{

    bool l_ok = true;

    l_ok &= check_hash("Hello world"
                      , {0x7b502c3a
                        , 0x1f48c860
                        , 0x9ae212cd
                        , 0xfb639dee
                        , 0x39673f5e
                        }
                      );

    l_ok &= check_hash( "a"
                      , { 0x86f7e437
                        , 0xfaa5a7fc
                        , 0xe15d1ddc
                        , 0xb9eaeaea
                        , 0x377667b8
                        }
                      );

    l_ok &= check_hash("abc"
                      , { 0xa9993e36
                        , 0x4706816a
                        , 0xba3e2571
                        , 0x7850c26c
                        , 0x9cd0d89d
                        }
                      );

    l_ok &= check_hash( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                      , {0x84983e44
                        , 0x1c3bd26e
                        , 0xbaae4aa1
                        , 0xf95129e5
                        , 0xe54670f1
                        }
                      );

    l_ok &= check_hash( "0123456701234567012345670123456701234567012345670123456701234567"
                      , { 0xe0c094e8
                        , 0x67ef46c3
                        , 0x50ef54a7
                        , 0xf59dd60b
                        , 0xed92ae83
                        }
                      );

    std::cout << quicky_utils::set_fcolor(l_ok ? quicky_utils::ansi_color::green : quicky_utils::ansi_color::red);
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "- TEST " << (l_ok ? "PASSED" : "FAILED") << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    return !l_ok;
}
#endif // SHA1_SELF_TEST
// EOF