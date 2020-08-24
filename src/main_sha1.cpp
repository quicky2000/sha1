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
using namespace std;

int main(void)
{
  cout << "Hello world" << endl ;
  char  l_sentence[] = "Hello world";
  // char  l_sentence[] = "abc";
  // char  l_sentence[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  // char  l_sentence[] = "0123456701234567012345670123456701234567012345670123456701234567";
  sha1(l_sentence,8 * strlen(l_sentence));
}
#endif // SHA1_SELF_TEST
// EOF