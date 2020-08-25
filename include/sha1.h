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
#ifndef SHA1_H
#define SHA1_H

#include <cstdint>

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cassert>

class sha1
{
  public:
    inline
    sha1( const char * p_data
        , uint64_t p_size
        );

    inline
    uint32_t get_key(unsigned int p_index) const;

  private:

    inline static
    uint32_t get_constant(uint32_t p_index);

    inline static
    uint32_t f( uint32_t x
              , uint32_t y
              , uint32_t z
              , uint32_t i
              );

    inline static
    uint32_t ch( uint32_t x
               , uint32_t y
               , uint32_t z
               );

    inline static
    uint32_t parity( uint32_t x
                   , uint32_t y
                   , uint32_t z
                   );

    inline static
    uint32_t maj( uint32_t x
                , uint32_t y
                , uint32_t z
                );

    inline static
    uint32_t rotl( uint32_t x
                 , uint32_t n
                 );

    inline static
    void display_block(const uint32_t (&p_block)[16]);

    inline
    void display_key()const;

    uint32_t m_key[5];
    uint32_t m_words[80];
    static const uint32_t m_constants[4];
};

//------------------------------------------------------------------------------
sha1::sha1( const char * p_data
          , uint64_t p_size_bit
          )
          : m_key{ 0x67452301
                  , 0xefcdab89
                  , 0x98badcfe
                  , 0x10325476
                  , 0xc3d2e1f0
                  }
          , m_words{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   , 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                   }

{
    std::cout << "Size in bit = " << p_size_bit << " => 0x" << std::hex << p_size_bit << std::dec << std::endl ;

    // Computing length complement
    uint32_t l_complement_size = (448 - (p_size_bit + 1 )) % 512;
    std::cout << "Number of padding zeros = " << l_complement_size << std::endl ;
  
    uint32_t l_nb_blocks = ( p_size_bit + 1 + l_complement_size + 64) / 512;
  
    std::cout << "Nb blocks = " << l_nb_blocks << std::endl ;

    // Loop on data blocks
    for(uint64_t l_block_index = 0; l_block_index < l_nb_blocks ; ++l_block_index)
    {
        //Working block
        uint32_t l_working_block[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

        // Init block with datas
        //--------------------------
        std::cout <<  "Prepare block[" << l_block_index << "]" << std::endl ;

        // Check if we are in a complete block
        std::cout << "check if this is a complete block" << std::endl;
        if((l_block_index + 1) * 512 <= p_size_bit)
        {
            std::cout <<  "Copy complete block" << std::endl ;
            for(uint32_t l_byte_index = 0; l_byte_index < 64; ++l_byte_index)
            {
                l_working_block[l_byte_index / 4] |= p_data[l_byte_index] << (24 - 8 * (l_byte_index % 4 ));
            }
        }
        else
        {
            uint32_t l_rest_size_bits = (p_size_bit % 512 );
            uint32_t l_rest_size_word = 1 + l_rest_size_bits / 32;
            std::cout << "size of incomplete block in bits = " << l_rest_size_bits << std::endl ;
            std::cout << "size of incomplete block in word = " << l_rest_size_word << std::endl ;
            // Check if there are remaining datas to copy
            std::cout << "Check if there are less than 512 data bits to copy" << std::endl ;
            if((l_block_index * 512 + l_rest_size_bits) == p_size_bit)
            {
                std::cout <<  "Copy partial block" << std::endl ;
                //	  display_block(l_working_block);
                for(uint32_t l_byte_index = 0; l_byte_index < l_rest_size_bits / 8; ++l_byte_index)
                {
                    l_working_block[l_byte_index / 4] |= p_data[l_byte_index] << (24 - 8 * (l_byte_index % 4 ));
                }
                display_block(l_working_block);
            }

            uint32_t l_reset_word_start_index = 0;
            uint32_t l_reset_word_end_index = 16;
            // Check if we are in the block where to put the additional 1 bit
            std::cout << "Check if we are in the block where to put the additional 1 bit" << std::endl ;
            if((p_size_bit  / 512) == l_block_index)
            {
                std::cout << "Setting additional bit to 1" << std::endl ;
                // Setting one additional bit to 1
                std::cout << "Index of block where to set the additional bit to 1 = " << (l_rest_size_bits / 32) << std::endl ;
                std::cout << "Shifting of " << (31 - l_rest_size_bits) << std::endl ;
                std::cout << "Mask = 0x" << std::hex <<  ( 1 << (31 - l_rest_size_bits)) << std::dec<< std::endl ;
                l_working_block[(l_rest_size_bits) / 32] |=  1 << (31 - l_rest_size_bits);
	      
                //	  display_block(l_working_block);
	      
                l_reset_word_start_index = 1 + ((l_rest_size_bits + 2) / 32);
            }

            // Adding the size
            std::cout << "Check if we are in the latest block" << std::endl;
            if(l_block_index + 1 == l_nb_blocks)
            {
                std::cout << "Adding the size" << std::endl ;
                l_working_block[14] = p_size_bit >> 32;
                l_working_block[15] = (uint32_t)(p_size_bit & 0xFFFFFFFF);
                l_reset_word_end_index = 14;
            }

            // Setting rest of word to 0
            for(uint32_t l_word_index = l_reset_word_start_index ; l_word_index < l_reset_word_end_index; ++l_word_index)
            {
                std::cout << "Setting word[" << l_word_index << "] to 0" << std::endl ;
                l_working_block[l_word_index] = 0;
            }

            //	  display_block(l_working_block);
        }

        // Display block to treat
        //---------------------------
        display_block(l_working_block);

        // Initialising word array
        //----------------------------
        // The 16 first words are the data themself
        memcpy(m_words,l_working_block,64);

        // Computing the other words
        for(uint32_t l_word_index = 16;l_word_index < 80; ++l_word_index)
        {
            std::cout << "Computing Word[" << l_word_index << "]" << std::endl ;
            m_words[l_word_index] = rotl(m_words[l_word_index - 3] ^ m_words[l_word_index - 8] ^ m_words[l_word_index - 14] ^ m_words[l_word_index - 16],1);
        }

        //display words
        for(uint32_t l_word_index = 0;l_word_index < 80; ++l_word_index)
        {
            std::cout << "Word["<< l_word_index <<"] = 0x" << std::hex << m_words[l_word_index] << std::dec << std::endl ;
        }


        // Initialising variables
        //-------------------------
        uint32_t a = m_key[0];
        uint32_t b = m_key[1];
        uint32_t c = m_key[2];
        uint32_t d = m_key[3];
        uint32_t e = m_key[4];

        // Performing the "round"
        //-------------------------
        for(uint32_t l_round_index = 0; l_round_index < 80 ; ++l_round_index)
        {
            std::cout << "Performing round " << l_round_index << std::endl ;
            uint32_t l_temp = rotl(a,5) + f(b, c, d, l_round_index) + e + get_constant(l_round_index) + m_words[l_round_index];
            e = d;
            d = c;
            c= rotl(b,30);
            b = a;
            a = l_temp;
        }

        // Computing intermediate hash value
        m_key[0] = a + m_key[0];
        m_key[1] = b + m_key[1];
        m_key[2] = c + m_key[2];
        m_key[3] = d + m_key[3];
        m_key[4] = e + m_key[4];

        std::cout << "Hash Value of block[" << l_block_index << "] =  ";
        display_key();
        std::cout << std::endl ;
    }
    std::cout << "Hash Value =  ";
    display_key();
    std::cout << std::endl ;
}

//------------------------------------------------------------------------------
void sha1::display_key() const
{
    std::cout << "0x" << std::hex ;
    for(auto l_iter: m_key)
    {
        std::cout << l_iter << " ";
    }
    std::cout << std::dec;
}

//------------------------------------------------------------------------------
void sha1::display_block(const uint32_t (&p_block)[16])
{
    std:: cout << "------------------------" << std::endl ;
    // Display block
    for(uint32_t l_word_index = 0 ; l_word_index < 16; ++l_word_index)
    {
        std::cout << "Word[" << l_word_index << "] = 0x" << std::hex << p_block[l_word_index] << std::dec << std::endl ;
    }
}

//------------------------------------------------------------------------------
uint32_t sha1::get_constant(uint32_t p_index)
{
    return m_constants[p_index / 20];
}

//------------------------------------------------------------------------------
uint32_t sha1::f( uint32_t x
                , uint32_t y
                , uint32_t z
                , uint32_t i
                )
{
    uint32_t l_result;
    switch(i / 20)
    {
        case 0:
            l_result = ch(x, y, z);
            break;
        case 1:
        case 3:
            l_result = parity(x, y, z);
            break;
        case 2:
            l_result = maj(x, y, z);
            break;
    }
    return l_result;
}

//------------------------------------------------------------------------------
uint32_t sha1::ch( uint32_t x
                 , uint32_t y
                 , uint32_t z
                 )
{
    return (x & y ) ^ ( (~x) & z );
}

//------------------------------------------------------------------------------
uint32_t sha1::parity( uint32_t x
                     , uint32_t y
                     , uint32_t z
                     )
{
    return x ^ y ^ z;
}

//------------------------------------------------------------------------------
uint32_t sha1::maj( uint32_t x
                  , uint32_t y
                  , uint32_t z
                  )
{
    return (x & y ) ^ ( x & z ) ^ ( y & z );
}

//------------------------------------------------------------------------------
uint32_t sha1::rotl( uint32_t x
                   , uint32_t n
                   )
{
    return ( x << n) | ( x >> ( 32 - n) );
}

//------------------------------------------------------------------------------
uint32_t
sha1::get_key(unsigned int p_index) const
{
    assert(p_index < 5);
    return m_key[p_index];
}

#endif // SHA1_H
// EOF