#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

#include <iostream>
#include <iomanip>
#include <string.h>

class sha1
{
 public:
  inline sha1(const char *p_data,uint64_t p_size);
  
 private:
  inline static const uint32_t get_constant(const uint32_t p_index);
  inline static const uint32_t f(const uint32_t & x,const uint32_t & y,const uint32_t & z,const uint32_t i);
  inline static const uint32_t ch(const uint32_t & x,const uint32_t & y,const uint32_t & z);
  inline static const uint32_t parity(const uint32_t & x,const uint32_t & y,const uint32_t & z);
  inline static const uint32_t maj(const uint32_t & x,const uint32_t & y,const uint32_t & z);
  inline static const uint32_t rotl(const uint32_t & x,const uint32_t i);
  inline void treat_block(const uint32_t (&p_block)[16]);
  inline void display_block(const uint32_t (&p_block)[16]);
  inline void display_key(void)const;
  

  uint32_t m_key[5];
  uint32_t m_words[80];
  static const uint32_t m_constants[4];
};

//------------------------------------------------------------------------------
sha1::sha1(const char *p_data,uint64_t p_size_bit)
{
  std::cout << "Size in bit = " << p_size_bit << " => 0x" << std::hex << p_size_bit << std::dec << std::endl ;

  // Computing length complement
  uint32_t l_complement_size = (448 - (p_size_bit + 1 )) % 512;
  std::cout << "Number of padding zeros = " << l_complement_size << std::endl ;
  
  uint32_t l_nb_blocks = ( p_size_bit + 1 + l_complement_size + 64)/512;
  
  std::cout << "Nb blocks = " << l_nb_blocks << std::endl ;

  //Initialising hash key
  m_key[0] = 0x67452301;
  m_key[1] = 0xefcdab89;
  m_key[2] = 0x98badcfe;
  m_key[3] = 0x10325476;
  m_key[4] = 0xc3d2e1f0;

  // Loop on data blocks
  for(uint64_t l_block_index=0; l_block_index < l_nb_blocks ; ++l_block_index)
    {
      //Working block
      uint32_t l_working_block[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

      // Init block with datas
      //--------------------------
      std::cout <<  "Prepare block[" << l_block_index << "]" << std::endl ;

      // Check if we are in a complete block
      std::cout << "check if this is a complete block" << std::endl;
      if((l_block_index+1) * 512 <= p_size_bit)
	{
	  std::cout <<  "Copy complete block" << std::endl ;
	  for(uint32_t l_byte_index=0;l_byte_index<64;++l_byte_index)
	    {
	      
	      l_working_block[l_byte_index/4] |= p_data[l_byte_index] << 24 - 8 * (l_byte_index % 4 );
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
	      
	      for(uint32_t l_byte_index=0;l_byte_index<l_rest_size_bits/8;++l_byte_index)
	      	{
	      	  
	      	  l_working_block[l_byte_index/4] |= p_data[l_byte_index] << 24 - 8 * (l_byte_index % 4 );
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
	      std::cout << "Index of block where to set the additional bit to 1 = " << (l_rest_size_bits)/32 << std::endl ;
	      std::cout << "Shifting of " << (31-l_rest_size_bits) << std::endl ;
	      std::cout << "Mask = 0x" << std::hex <<  ( 1 << (31-l_rest_size_bits)) << std::dec<< std::endl ;
	      l_working_block[(l_rest_size_bits)/32] |=  1 << (31-l_rest_size_bits);
	      
	      //	  display_block(l_working_block);
	      
	      l_reset_word_start_index = 1+((l_rest_size_bits+2)/32);
	      
	    }


	  // Adding the size
	  std::cout << "Check if we are in the latest block" << std::endl;
	  if(l_block_index+1 == l_nb_blocks)
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
	  m_words[l_word_index] = rotl(m_words[l_word_index-3] ^ m_words[l_word_index-8] ^ m_words[l_word_index-14] ^ m_words[l_word_index-16],1);
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
      for(uint32_t l_round_index = 0;l_round_index < 80 ; ++l_round_index)
	{
	  std::cout << "Performing round " << l_round_index << std::endl ;
	  uint32_t l_temp = rotl(a,5) + f(b,c,d,l_round_index)+e+get_constant(l_round_index)+m_words[l_round_index];
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
void sha1::display_key(void)const
{
  std::cout << "0x" << std::hex ; 
  for(uint32_t l_key_index = 0 ; l_key_index < 5 ; ++l_key_index)
    {
      std::cout << m_key[l_key_index] << " ";
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
const uint32_t sha1::get_constant(const uint32_t p_index)
{
  return m_constants[p_index / 20];
}

//------------------------------------------------------------------------------
const uint32_t sha1::f(const uint32_t & x,const uint32_t & y,const uint32_t & z,const uint32_t i)
{
  uint32_t l_result;
  switch(i/20)
    {
    case 0:
      l_result = ch(x, y, z);
      break;
    case 1:
    case 3:
      l_result = parity(x,y,z);
      break;
    case 2:
      l_result = maj(x,y,z);
      break;
    }
  return l_result;
}

//------------------------------------------------------------------------------
const uint32_t sha1::ch(const uint32_t & x,const uint32_t & y,const uint32_t & z)
{
  return (x & y ) ^ ( (~x) & z );
}

//------------------------------------------------------------------------------
const uint32_t sha1::parity(const uint32_t & x,const uint32_t & y,const uint32_t & z)
{
  return x ^ y ^ z;
}

//------------------------------------------------------------------------------
const uint32_t sha1::maj(const uint32_t & x,const uint32_t & y,const uint32_t & z)
{
  return (x & y ) ^ ( x & z ) ^ ( y & z );
}

//------------------------------------------------------------------------------
const uint32_t sha1::rotl(const uint32_t & x,const uint32_t n)
{
  return ( x << n) | ( x >> ( 32 - n) );
}
#endif
