/*
    This file is part of sha1
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
#include "sha1.h"

const std::array<uint32_t,4> sha1::m_constants =
  {{ 0x5a827999 // 0 to 19
   , 0x6ed9eba1 //20 to 39
   , 0x8f1bbcdc //40 to 59
   , 0xca62c1d6  //60 to 79
  }};

//EOF
