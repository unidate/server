/* Copyright (c) 2011, 2013, Oracle and/or its affiliates. All rights reserved.
   Copyright (c) 2014 MariaDB Foundation

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include "mariadb.h"
#include "item_inetfunc.h"

#include "my_net.h"

///////////////////////////////////////////////////////////////////////////

static const size_t IN_ADDR_SIZE= 4;
static const size_t IN6_ADDR_SIZE= 16;
static const size_t IN6_ADDR_NUM_WORDS= IN6_ADDR_SIZE / 2;

/**
  Non-abbreviated syntax is 8 groups, up to 4 digits each,
  plus 7 delimiters between the groups.
  Abbreviated syntax is even shorter.
*/
static const uint IN6_ADDR_MAX_CHAR_LENGTH= 8 * 4 + 7;

static const char HEX_DIGITS[]= "0123456789abcdef";


class NativeBufferInet6: public NativeBuffer<IN6_ADDR_SIZE+1>
{
};

class StringBufferInet6: public StringBuffer<IN6_ADDR_MAX_CHAR_LENGTH+1>
{
};

///////////////////////////////////////////////////////////////////////////

longlong Item_func_inet_aton::val_int()
{
  DBUG_ASSERT(fixed);

  uint byte_result= 0;
  ulonglong result= 0;                    // We are ready for 64 bit addresses
  const char *p,* end;
  char c= '.'; // we mark c to indicate invalid IP in case length is 0
  int dot_count= 0;

  StringBuffer<36> tmp;
  String *s= args[0]->val_str_ascii(&tmp);

  if (!s)       // If null value
    goto err;

  null_value= 0;

  end= (p = s->ptr()) + s->length();
  while (p < end)
  {
    c= *p++;
    int digit= (int) (c - '0');
    if (digit >= 0 && digit <= 9)
    {
      if ((byte_result= byte_result * 10 + digit) > 255)
        goto err;                               // Wrong address
    }
    else if (c == '.')
    {
      dot_count++;
      result= (result << 8) + (ulonglong) byte_result;
      byte_result= 0;
    }
    else
      goto err;                                 // Invalid character
  }
  if (c != '.')                                 // IP number can't end on '.'
  {
    /*
      Attempt to support short forms of IP-addresses. It's however pretty
      basic one comparing to the BSD support.
      Examples:
        127     -> 0.0.0.127
        127.255 -> 127.0.0.255
        127.256 -> NULL (should have been 127.0.1.0)
        127.2.1 -> 127.2.0.1
    */
    switch (dot_count) {
    case 1: result<<= 8; /* Fall through */
    case 2: result<<= 8; /* Fall through */
    }
    return (result << 8) + (ulonglong) byte_result;
  }

err:
  null_value=1;
  return 0;
}


String* Item_func_inet_ntoa::val_str(String* str)
{
  DBUG_ASSERT(fixed);

  ulonglong n= (ulonglong) args[0]->val_int();

  /*
    We do not know if args[0] is NULL until we have called
    some val function on it if args[0] is not a constant!

    Also return null if n > 255.255.255.255
  */
  if ((null_value= (args[0]->null_value || n > 0xffffffff)))
    return 0;                                   // Null value

  str->set_charset(collation.collation);
  str->length(0);

  uchar buf[8];
  int4store(buf, n);

  /* Now we can assume little endian. */

  char num[4];
  num[3]= '.';

  for (uchar *p= buf + 4; p-- > buf;)
  {
    uint c= *p;
    uint n1, n2;                                // Try to avoid divisions
    n1= c / 100;                                // 100 digits
    c-= n1 * 100;
    n2= c / 10;                                 // 10 digits
    c-= n2 * 10;                                // last digit
    num[0]= (char) n1 + '0';
    num[1]= (char) n2 + '0';
    num[2]= (char) c + '0';
    uint length= (n1 ? 4 : n2 ? 3 : 2);         // Remove pre-zero
    uint dot_length= (p <= buf) ? 1 : 0;
    (void) str->append(num + 4 - length, length - dot_length,
                       &my_charset_latin1);
  }

  return str;
}

///////////////////////////////////////////////////////////////////////////


class Inet4
{
  char m_buffer[IN_ADDR_SIZE];
protected:
  bool str_to_ipv4(const char *str, size_t length, CHARSET_INFO *cs);
  bool binary_to_ipv4(const char *str, size_t length)
  {
    if (length != sizeof(m_buffer))
      return true;
    memcpy(m_buffer, str, length);
    return false;
  }
  // Non-initializing constructor
  Inet4() { }
public:
  void to_binary(char *dst, size_t dstsize) const
  {
    DBUG_ASSERT(dstsize >= sizeof(m_buffer));
    memcpy(dst, m_buffer, sizeof(m_buffer));
  }
  bool to_binary(String *to) const
  {
    return to->copy(m_buffer, sizeof(m_buffer), &my_charset_bin);
  }
  size_t to_string(char *dst, size_t dstsize) const;
  bool to_string(String *to) const
  {
    to->set_charset(&my_charset_latin1);
    if (to->alloc(INET_ADDRSTRLEN))
      return true;
    to->length((uint32) to_string((char*) to->ptr(), INET_ADDRSTRLEN));
    return false;
  }
};


class Inet4_null: public Inet4, public Null_flag
{
public:
  // Initialize from a text representation
  Inet4_null(const char *str, size_t length, CHARSET_INFO *cs)
   :Null_flag(str_to_ipv4(str, length, cs))
  { }
  Inet4_null(const String &str)
   :Inet4_null(str.ptr(), str.length(), str.charset())
  { }
  // Initialize from a binary representation
  Inet4_null(const char *str, size_t length)
   :Null_flag(binary_to_ipv4(str, length))
  { }
  Inet4_null(const Binary_string &str)
   :Inet4_null(str.ptr(), str.length())
  { }
public:
  const Inet4& to_inet4() const
  {
    DBUG_ASSERT(!is_null());
    return *this;
  }
  void to_binary(char *dst, size_t dstsize) const
  {
    to_inet4().to_binary(dst, dstsize);
  }
  bool to_binary(String *to) const
  {
    return to_inet4().to_binary(to);
  }
  size_t to_string(char *dst, size_t dstsize) const
  {
    return to_inet4().to_string(dst, dstsize);
  }
  bool to_string(String *to) const
  {
    return to_inet4().to_string(to);
  }
};


class Inet6
{
  char m_buffer[IN6_ADDR_SIZE];
protected:
  bool make_from_item(Item *item);
  bool make_from_field(Field *field);
  bool str_to_ipv6(const char *str, size_t str_length, CHARSET_INFO *cs);
  bool binary_to_ipv6(const char *str, size_t length)
  {
    if (length != sizeof(m_buffer))
      return true;
    memcpy(m_buffer, str, length);
    return false;
  }
  // Non-initializing constructor
  Inet6() { }

public:
  static uint binary_length() { return IN6_ADDR_SIZE; }
  /**
    Non-abbreviated syntax is 8 groups, up to 4 digits each,
    plus 7 delimiters between the groups.
    Abbreviated syntax is even shorter.
  */
  static uint max_char_length() { return IN6_ADDR_MAX_CHAR_LENGTH; }

  static bool only_zero_bytes(const char *ptr, uint length)
  {
    for (uint i= 0 ; i < length; i++)
    {
      if (ptr[i] != 0)
        return false;
    }
    return true;
  }

public:
  void to_binary(char *str, size_t str_size) const
  {
    DBUG_ASSERT(str_size >= sizeof(m_buffer));
    memcpy(str, m_buffer, sizeof(m_buffer));
  }
  bool to_binary(String *to) const
  {
    return to->copy(m_buffer, sizeof(m_buffer), &my_charset_bin);
  }
  bool to_native(Native *to) const
  {
    return to->copy(m_buffer, sizeof(m_buffer));
  }
  size_t to_string(char *dst, size_t dstsize) const;
  bool to_string(String *to) const
  {
    to->set_charset(&my_charset_latin1);
    if (to->alloc(INET6_ADDRSTRLEN))
      return true;
    to->length((uint32) to_string((char*) to->ptr(), INET6_ADDRSTRLEN));
    return false;
  }
  bool is_v4compat() const
  {
    static_assert(sizeof(in6_addr) == IN6_ADDR_SIZE, "unexpected in6_addr size");
    return IN6_IS_ADDR_V4COMPAT((struct in6_addr *) m_buffer);
  }
  bool is_v4mapped() const
  {
    static_assert(sizeof(in6_addr) == IN6_ADDR_SIZE, "unexpected in6_addr size");
    return IN6_IS_ADDR_V4MAPPED((struct in6_addr *) m_buffer);
  }
  int cmp(const Inet6 &other) const
  {
    return memcmp(m_buffer, other.m_buffer, sizeof(m_buffer));
  }
};


class Inet6_null: public Inet6, public Null_flag
{
public:
  // Initialize from a text representation
  Inet6_null(const char *str, size_t length, CHARSET_INFO *cs)
   :Null_flag(str_to_ipv6(str, length, cs))
  { }
  Inet6_null(const String &str)
   :Inet6_null(str.ptr(), str.length(), str.charset())
  { }
  // Initialize from a binary representation
  Inet6_null(const char *str, size_t length)
   :Null_flag(binary_to_ipv6(str, length))
  { }
  Inet6_null(const Binary_string &str)
   :Inet6_null(str.ptr(), str.length())
  { }
  // Initialize from an Item
  Inet6_null(Item *item)
   :Null_flag(make_from_item(item))
  { }
  // Initialize from a Field
  Inet6_null(Field *field)
   :Null_flag(make_from_field(field))
  { }
public:
  const Inet6& to_inet6() const
  {
    DBUG_ASSERT(!is_null());
    return *this;
  }
  void to_binary(char *str, size_t str_size) const
  {
    to_inet6().to_binary(str, str_size);
  }
  bool to_binary(String *to) const
  {
    return to_inet6().to_binary(to);
  }
  size_t to_string(char *dst, size_t dstsize) const
  {
    return to_inet6().to_string(dst, dstsize);
  }
  bool to_string(String *to) const
  {
    return to_inet6().to_string(to);
  }
  bool is_v4compat() const
  {
    return to_inet6().is_v4compat();
  }
  bool is_v4mapped() const
  {
    return to_inet6().is_v4mapped();
  }
};


/**
  Tries to convert given string to binary IPv4-address representation.
  This is a portable alternative to inet_pton(AF_INET).

  @param      str          String to convert.
  @param      str_length   String length.

  @return Completion status.
  @retval true  - error, the given string does not represent an IPv4-address.
  @retval false - ok, the string has been converted sucessfully.

  @note The problem with inet_pton() is that it treats leading zeros in
  IPv4-part differently on different platforms.
*/

bool Inet4::str_to_ipv4(const char *str, size_t str_length, CHARSET_INFO *cs)
{
  DBUG_ASSERT(cs->mbminlen == 1);
  if (str_length < 7)
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): "
                         "invalid IPv4 address: too short.",
                         (int) str_length, str));
    return true;
  }

  if (str_length > 15)
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): "
                         "invalid IPv4 address: too long.",
                         (int) str_length, str));
    return true;
  }

  unsigned char *ipv4_bytes= (unsigned char *) &m_buffer;
  const char *str_end= str + str_length;
  const char *p= str;
  int byte_value= 0;
  int chars_in_group= 0;
  int dot_count= 0;
  char c= 0;

  while (p < str_end && *p)
  {
    c= *p++;

    if (my_isdigit(&my_charset_latin1, c))
    {
      ++chars_in_group;

      if (chars_in_group > 3)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "too many characters in a group.",
                             (int) str_length, str));
        return true;
      }

      byte_value= byte_value * 10 + (c - '0');

      if (byte_value > 255)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "invalid byte value.",
                             (int) str_length, str));
        return true;
      }
    }
    else if (c == '.')
    {
      if (chars_in_group == 0)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "too few characters in a group.",
                             (int) str_length, str));
        return true;
      }

      ipv4_bytes[dot_count]= (unsigned char) byte_value;

      ++dot_count;
      byte_value= 0;
      chars_in_group= 0;

      if (dot_count > 3)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "too many dots.", (int) str_length, str));
        return true;
      }
    }
    else
    {
      DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                           "invalid character at pos %d.",
                           (int) str_length, str, (int) (p - str)));
      return true;
    }
  }

  if (c == '.')
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                         "ending at '.'.", (int) str_length, str));
    return true;
  }

  if (dot_count != 3)
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                         "too few groups.",
                         (int) str_length, str));
    return true;
  }

  ipv4_bytes[3]= (unsigned char) byte_value;

  DBUG_PRINT("info", ("str_to_ipv4(%.*s): valid IPv4 address: %d.%d.%d.%d",
                      (int) str_length, str,
                      ipv4_bytes[0], ipv4_bytes[1],
                      ipv4_bytes[2], ipv4_bytes[3]));
  return false;
}


/**
  Tries to convert given string to binary IPv6-address representation.
  This is a portable alternative to inet_pton(AF_INET6).

  @param      str          String to convert.
  @param      str_length   String length.

  @return Completion status.
  @retval true  - error, the given string does not represent an IPv6-address.
  @retval false - ok, the string has been converted sucessfully.

  @note The problem with inet_pton() is that it treats leading zeros in
  IPv4-part differently on different platforms.
*/

bool Inet6::str_to_ipv6(const char *str, size_t str_length, CHARSET_INFO *cs)
{
  // QQ: it currently crashes with collation_connection=ucs2_general_ci
  DBUG_ASSERT(cs->mbminlen == 1);

  if (str_length < 2)
  {
    DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: too short.",
                         (int) str_length, str));
    return true;
  }

  if (str_length > IN6_ADDR_MAX_CHAR_LENGTH)
  {
    DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: too long.",
                         (int) str_length, str));
    return true;
  }

  memset(m_buffer, 0, sizeof(m_buffer));

  const char *p= str;

  if (*p == ':')
  {
    ++p;

    if (*p != ':')
    {
      DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                           "can not start with ':x'.", (int) str_length, str));
      return true;
    }
  }

  const char *str_end= str + str_length;
  char *ipv6_bytes_end= m_buffer + sizeof(m_buffer);
  char *dst= m_buffer;
  char *gap_ptr= NULL;
  const char *group_start_ptr= p;
  int chars_in_group= 0;
  int group_value= 0;

  while (p < str_end && *p)
  {
    char c= *p++;

    if (c == ':')
    {
      group_start_ptr= p;

      if (!chars_in_group)
      {
        if (gap_ptr)
        {
          DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                               "too many gaps(::).", (int) str_length, str));
          return true;
        }

        gap_ptr= dst;
        continue;
      }

      if (!*p || p >= str_end)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "ending at ':'.", (int) str_length, str));
        return true;
      }

      if (dst + 2 > ipv6_bytes_end)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "too many groups (1).", (int) str_length, str));
        return true;
      }

      dst[0]= (unsigned char) (group_value >> 8) & 0xff;
      dst[1]= (unsigned char) group_value & 0xff;
      dst += 2;

      chars_in_group= 0;
      group_value= 0;
    }
    else if (c == '.')
    {
      if (dst + IN_ADDR_SIZE > ipv6_bytes_end)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "unexpected IPv4-part.", (int) str_length, str));
        return true;
      }

      Inet4_null tmp(group_start_ptr, (size_t) (str_end - group_start_ptr), cs);
      if (tmp.is_null())
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "invalid IPv4-part.", (int) str_length, str));
        return true;
      }

      tmp.to_binary(dst, IN_ADDR_SIZE);
      dst += IN_ADDR_SIZE;
      chars_in_group= 0;

      break;
    }
    else
    {
      const char *hdp= strchr(HEX_DIGITS, my_tolower(&my_charset_latin1, c));

      if (!hdp)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "invalid character at pos %d.",
                             (int) str_length, str, (int) (p - str)));
        return true;
      }

      if (chars_in_group >= 4)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "too many digits in group.",
                             (int) str_length, str));
        return true;
      }

      group_value <<= 4;
      group_value |= hdp - HEX_DIGITS;

      DBUG_ASSERT(group_value <= 0xffff);

      ++chars_in_group;
    }
  }

  if (chars_in_group > 0)
  {
    if (dst + 2 > ipv6_bytes_end)
    {
      DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                           "too many groups (2).", (int) str_length, str));
      return true;
    }

    dst[0]= (unsigned char) (group_value >> 8) & 0xff;
    dst[1]= (unsigned char) group_value & 0xff;
    dst += 2;
  }

  if (gap_ptr)
  {
    if (dst == ipv6_bytes_end)
    {
      DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                           "no room for a gap (::).", (int) str_length, str));
      return true;
    }

    int bytes_to_move= (int)(dst - gap_ptr);

    for (int i= 1; i <= bytes_to_move; ++i)
    {
      ipv6_bytes_end[-i]= gap_ptr[bytes_to_move - i];
      gap_ptr[bytes_to_move - i]= 0;
    }

    dst= ipv6_bytes_end;
  }

  if (dst < ipv6_bytes_end)
  {
    DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                         "too few groups.", (int) str_length, str));
    return true;
  }

  return false;
}


/**
  Converts IPv4-binary-address to a string. This function is a portable
  alternative to inet_ntop(AF_INET).

  @param[in] ipv4 IPv4-address data (byte array)
  @param[out] dst A buffer to store string representation of IPv4-address.
  @param[in]  dstsize Number of bytes avaiable in "dst"

  @note The problem with inet_ntop() is that it is available starting from
  Windows Vista, but the minimum supported version is Windows 2000.
*/

size_t Inet4::to_string(char *dst, size_t dstsize) const
{
  return (size_t) my_snprintf(dst, dstsize, "%d.%d.%d.%d",
                              (uchar) m_buffer[0], (uchar) m_buffer[1],
                              (uchar) m_buffer[2], (uchar) m_buffer[3]);
}


/**
  Converts IPv6-binary-address to a string. This function is a portable
  alternative to inet_ntop(AF_INET6).

  @param[in] ipv6 IPv6-address data (byte array)
  @param[out] dst A buffer to store string representation of IPv6-address.
                  It must be at least of INET6_ADDRSTRLEN.
  @param[in] dstsize Number of bytes available dst.

  @note The problem with inet_ntop() is that it is available starting from
  Windows Vista, but out the minimum supported version is Windows 2000.
*/

size_t Inet6::to_string(char *dst, size_t dstsize) const
{
  struct Region
  {
    int pos;
    int length;
  };

  const char *ipv6= m_buffer;
  char *dstend= dst + dstsize;
  const unsigned char *ipv6_bytes= (const unsigned char *) ipv6;

  // 1. Translate IPv6-address bytes to words.
  // We can't just cast to short, because it's not guaranteed
  // that sizeof (short) == 2. So, we have to make a copy.

  uint16 ipv6_words[IN6_ADDR_NUM_WORDS];

  DBUG_ASSERT(dstsize > 0); // Need a space at least for the trailing '\0'
  for (size_t i= 0; i < IN6_ADDR_NUM_WORDS; ++i)
    ipv6_words[i]= (ipv6_bytes[2 * i] << 8) + ipv6_bytes[2 * i + 1];

  // 2. Find "the gap" -- longest sequence of zeros in IPv6-address.

  Region gap= { -1, -1 };

  {
    Region rg= { -1, -1 };

    for (size_t i= 0; i < IN6_ADDR_NUM_WORDS; ++i)
    {
      if (ipv6_words[i] != 0)
      {
        if (rg.pos >= 0)
        {
          if (rg.length > gap.length)
            gap= rg;

          rg.pos= -1;
          rg.length= -1;
        }
      }
      else
      {
        if (rg.pos >= 0)
        {
          ++rg.length;
        }
        else
        {
          rg.pos= (int) i;
          rg.length= 1;
        }
      }
    }

    if (rg.pos >= 0)
    {
      if (rg.length > gap.length)
        gap= rg;
    }
  }

  // 3. Convert binary data to string.

  char *p= dst;

  for (int i= 0; i < (int) IN6_ADDR_NUM_WORDS; ++i)
  {
    DBUG_ASSERT(dstend >= p);
    size_t dstsize_available= dstend - p;
    if (dstsize_available < 5)
      break;
    if (i == gap.pos)
    {
      // We're at the gap position. We should put trailing ':' and jump to
      // the end of the gap.

      if (i == 0)
      {
        // The gap starts from the beginning of the data -- leading ':'
        // should be put additionally.

        *p= ':';
        ++p;
      }

      *p= ':';
      ++p;

      i += gap.length - 1;
    }
    else if (i == 6 && gap.pos == 0 &&
             (gap.length == 6 ||                           // IPv4-compatible
              (gap.length == 5 && ipv6_words[5] == 0xffff) // IPv4-mapped
             ))
    {
      // The data represents either IPv4-compatible or IPv4-mapped address.
      // The IPv6-part (zeros or zeros + ffff) has been already put into
      // the string (dst). Now it's time to dump IPv4-part.

      return (size_t) (p - dst) +
             Inet4_null((const char *) (ipv6_bytes + 12), 4).
               to_string(p, dstsize_available);
    }
    else
    {
      // Usual IPv6-address-field. Print it out using lower-case
      // hex-letters without leading zeros (recommended IPv6-format).
      //
      // If it is not the last field, append closing ':'.

      p += sprintf(p, "%x", ipv6_words[i]);

      if (i + 1 != IN6_ADDR_NUM_WORDS)
      {
        *p= ':';
        ++p;
      }
    }
  }

  *p= 0;
  return (size_t) (p - dst);
}

///////////////////////////////////////////////////////////////////////////

/**
  Converts IP-address-string to IP-address-data.

    ipv4-string -> varbinary(4)
    ipv6-string -> varbinary(16)

  @return Completion status.
  @retval NULL  Given string does not represent an IP-address.
  @retval !NULL The string has been converted sucessfully.
*/

String *Item_func_inet6_aton::val_str(String *buffer)
{
  DBUG_ASSERT(fixed);

  Ascii_ptr_and_buffer<STRING_BUFFER_USUAL_SIZE> tmp(args[0]);
  if ((null_value= tmp.is_null()))
    return NULL;

  Inet4_null ipv4(*tmp.string());
  if (!ipv4.is_null())
  {
    ipv4.to_binary(buffer);
    return buffer;
  }

  Inet6_null ipv6(*tmp.string());
  if (!ipv6.is_null())
  {
    ipv6.to_binary(buffer);
    return buffer;
  }

  null_value= true;
  return NULL;
}


/**
  Converts IP-address-data to IP-address-string.
*/

String *Item_func_inet6_ntoa::val_str_ascii(String *buffer)
{
  DBUG_ASSERT(fixed);

  // Binary string argument expected
  if (unlikely(args[0]->result_type() != STRING_RESULT ||
               args[0]->collation.collation != &my_charset_bin))
  {
    null_value= true;
    return NULL;
  }

  String_ptr_and_buffer<STRING_BUFFER_USUAL_SIZE> tmp(args[0]);
  if ((null_value= tmp.is_null()))
    return NULL;

  Inet4_null ipv4(static_cast<const Binary_string&>(*tmp.string()));
  if (!ipv4.is_null())
  {
    ipv4.to_string(buffer);
    return buffer;
  }

  Inet6_null ipv6(static_cast<const Binary_string&>(*tmp.string()));
  if (!ipv6.is_null())
  {
    ipv6.to_string(buffer);
    return buffer;
  }

  DBUG_PRINT("info", ("INET6_NTOA(): varbinary(4) or varbinary(16) expected."));
  null_value= true;
  return NULL;
}


/**
  Checks if the passed string represents an IPv4-address.
*/

longlong Item_func_is_ipv4::val_int()
{
  DBUG_ASSERT(fixed);
  String_ptr_and_buffer<STRING_BUFFER_USUAL_SIZE> tmp(args[0]);
  return !tmp.is_null() && !Inet4_null(*tmp.string()).is_null();
}


/**
  Checks if the passed string represents an IPv6-address.
*/

longlong Item_func_is_ipv6::val_int()
{
  DBUG_ASSERT(fixed);
  String_ptr_and_buffer<STRING_BUFFER_USUAL_SIZE> tmp(args[0]);
  return !tmp.is_null() && !Inet6_null(*tmp.string()).is_null();
}


/**
  Checks if the passed IPv6-address is an IPv4-compat IPv6-address.
*/

longlong Item_func_is_ipv4_compat::val_int()
{
  Inet6_null ip6(args[0]);
  return !ip6.is_null() && ip6.is_v4compat();
}


/**
  Checks if the passed IPv6-address is an IPv4-mapped IPv6-address.
*/

longlong Item_func_is_ipv4_mapped::val_int()
{
  Inet6_null ip6(args[0]);
  return !ip6.is_null() && ip6.is_v4mapped();
}


/********************************************************************/
#include "sql_class.h" // SORT_FIELD_ATTR
#include "opt_range.h" // SEL_ARG

extern SEL_ARG null_element;

class Type_std_attributes_inet6: public Type_std_attributes
{
public:
  Type_std_attributes_inet6()
   :Type_std_attributes(Inet6::max_char_length(), 0, true,
                        DTCollation(&my_charset_numeric,
                                    DERIVATION_NUMERIC,
                                    MY_REPERTOIRE_ASCII))
  { }
};


class Type_handler_inet6: public Type_handler
{
  static const Name m_name_inet6;
public:
  virtual ~Type_handler_inet6() {}

  virtual const Name name() const { return m_name_inet6; }
  virtual const Name version() const { return m_version_default; }
  virtual protocol_send_type_t protocol_send_type() const
  {
    return PROTOCOL_SEND_STRING;
  }

  virtual enum_field_types field_type() const
  {
    return MYSQL_TYPE_STRING;
  }


  virtual enum_field_types real_field_type() const
  {
    return (enum_field_types) 128;
  }

/*
  virtual enum_field_types traditional_merge_field_type() const
  {
    DBUG_ASSERT(is_traditional_type());
    return field_type();
  }
*/
  virtual Item_result result_type() const
  {
    return STRING_RESULT;
  }

  virtual Item_result cmp_type() const
  {
    return STRING_RESULT;
  }

/*
  virtual enum_mysql_timestamp_type mysql_timestamp_type() const
  {
    return MYSQL_TIMESTAMP_ERROR;
  }
  virtual bool is_timestamp_type() const
  {
    return false;
  }
  virtual bool is_order_clause_position_type() const
  {
    return false;
  }
  virtual bool is_limit_clause_valid_type() const
  {
    return false;
  }
*/
  /*
    Returns true if this data type supports a hack that
      WHERE notnull_column IS NULL
    finds zero values, e.g.:
      WHERE date_notnull_column IS NULL        ->
      WHERE date_notnull_column = '0000-00-00'
  */
/*
  virtual bool cond_notnull_field_isnull_to_field_eq_zero() const
  {
    return false;
  }
*/
  /**
    Check whether a field type can be partially indexed by a key.
    @param  type   field type
    @retval true   Type can have a prefixed key
    @retval false  Type can not have a prefixed key
  */
/*
  virtual bool type_can_have_key_part() const
  {
    return false;
  }
  virtual bool type_can_have_auto_increment_attribute() const
  {
    return false;
  }
*/
/*
  virtual uint max_octet_length() const { return 0; }
*/
  /**
    Prepared statement long data:
    Check whether this parameter data type is compatible with long data.
    Used to detect whether a long data stream has been supplied to a
    incompatible data type.
  */
/*
  virtual bool is_param_long_data_type() const { return false; }
*/
  virtual const Type_handler *type_handler_for_comparison() const
  {
    return this;
  }
/*
  virtual const Type_handler *type_handler_for_native_format() const
  {
    return this;
  }
  virtual const Type_handler *type_handler_for_item_field() const
  {
    return this;
  }
  virtual const Type_handler *type_handler_for_tmp_table(const Item *) const
  {
    return this;
  }
  virtual const Type_handler *type_handler_for_union(const Item *) const
  {
    return this;
  }
  virtual const Type_handler *cast_to_int_type_handler() const
  {
    return this;
  }
  virtual const Type_handler *type_handler_for_system_time() const
  {
    return this;
  }
*/
  virtual int
  stored_field_cmp_to_item(THD *thd, Field *field, Item *item) const
  {
    Inet6_null nf(field);
    Inet6_null ni(item);
    if (nf.is_null() || ni.is_null()) //QQ test this code
      return 0;
    return nf.cmp(ni);
  }
  virtual CHARSET_INFO *charset_for_protocol(const Item *item) const
  {
    return item->collation.collation;
  }
/*
  virtual const Type_handler*
  type_handler_adjusted_to_max_octet_length(uint max_octet_length,
                                            CHARSET_INFO *cs) const
  { return this; }
  virtual bool adjust_spparam_type(Spvar_definition *def, Item *from) const
  {
    return false;
  }
*/
  virtual bool is_traditional_type() const
  {
    return false;
  }
  virtual bool is_scalar_type() const { return true; }
  virtual bool can_return_int() const { return false; }
  virtual bool can_return_decimal() const { return false; }
  virtual bool can_return_real() const { return false; }
  virtual bool can_return_str() const { return true; }
  virtual bool can_return_text() const { return true; }
  virtual bool can_return_date() const { return false; }
  virtual bool can_return_time() const { return false; }

  //virtual bool is_bool_type() const { return false; }
  //virtual bool is_general_purpose_string_type() const { return false; }

  virtual uint Item_time_precision(THD *thd, Item *item) const
  {
    return 0;
  }
  virtual uint Item_datetime_precision(THD *thd, Item *item) const
  {
    return 0;
  }
  virtual uint Item_decimal_scale(const Item *item) const
  {
    return 0;
  }
  virtual uint Item_decimal_precision(const Item *item) const
  {
    /*
      This will be needed if we ever allow cast from INET6 to DECIMAL.
      Decimal precision of INET6 is 39 digits:
      'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' =
       340282366920938463463374607431768211456  = 39 digits
    */
    return 39;
  }

  /*
    Returns how many digits a divisor adds into a division result.
    See Item::divisor_precision_increment() in item.h for more comments.
  */
  virtual uint Item_divisor_precision_increment(const Item *) const
  {
    return 0;
  }
  /**
    Makes a temporary table Field to handle numeric aggregate functions,
    e.g. SUM(DISTINCT expr), AVG(DISTINCT expr), etc.
  */
  virtual Field *make_num_distinct_aggregator_field(MEM_ROOT *,
                                                    const Item *) const
  {
    DBUG_ASSERT(0);
    return 0;
  }
  virtual Field *make_conversion_table_field(TABLE *TABLE,
                                             uint metadata,
                                             const Field *target) const;
  // Automatic upgrade, e.g. for ALTER TABLE t1 FORCE
/*
  virtual void Column_definition_implicit_upgrade(Column_definition *c) const
  { }
*/
  // Validate CHECK constraint after the parser
/*
  virtual bool Column_definition_validate_check_constraint(THD *thd,
                                                           Column_definition *c)
                                                           const;
*/
  // Fix attributes after the parser
  virtual bool Column_definition_fix_attributes(Column_definition *c) const
  {
    c->length= Inet6::max_char_length();
    return false;
  }
  /*
    Fix attributes from an existing field. Used for:
    - ALTER TABLE (for columns that do not change)
    - DECLARE var TYPE OF t1.col1; (anchored SP variables)
  */
  /*
  virtual void Column_definition_reuse_fix_attributes(THD *thd,
                                                      Column_definition *c,
                                                      const Field *field) const
  { }
  */
  virtual bool Column_definition_prepare_stage1(THD *thd,
                                                MEM_ROOT *mem_root,
                                                Column_definition *def,
                                                handler *file,
                                                ulonglong table_flags) const
  {
    def->create_length_to_internal_length_simple();
    return false;
  }
  /*
    This method is called on queries like:
      CREATE TABLE t2 (a INT) AS SELECT a FROM t1;
    I.e. column "a" is queried from another table,
    but its data type is redefined.
    @param OUT def   - The column definition to be redefined
    @param IN  dup   - The column definition to take the data type from
                       (i.e. "a INT" in the above example).
    @param IN file   - Table owner handler. If it does not support certain
                       data types, some conversion can be applied.
                       I.g. true BIT to BIT-AS-CHAR.
    @param IN schema - the owner schema definition, e.g. for the default
                       character set and collation.
    @retval true     - on error
    @retval false    - on success
  */
  virtual bool Column_definition_redefine_stage1(Column_definition *def,
                                                 const Column_definition *dup,
                                                 const handler *file,
                                                 const Schema_specification_st *
                                                       schema)
                                                 const
  {
    def->redefine_stage1_common(dup, file, schema);
    def->set_compression_method(dup->compression_method());
    def->create_length_to_internal_length_string();
    return false;
  }
  virtual bool Column_definition_prepare_stage2(Column_definition *def,
                                                handler *file,
                                                ulonglong table_flags) const
  {
    def->pack_flag= FIELDFLAG_BINARY;
    return false;
  }
  virtual Field *make_table_field(const LEX_CSTRING *name,
                                  const Record_addr &addr,
                                  const Type_all_attributes &attr,
                                  TABLE *table) const;

  virtual Field *
  make_table_field_from_def(TABLE_SHARE *share,
                            MEM_ROOT *mem_root,
                            const LEX_CSTRING *name,
                            const Record_addr &addr,
                            const Bit_addr &bit,
                            const Column_definition_attributes *attr,
                            uint32 flags) const;
  virtual void
  Column_definition_attributes_frm_pack(const Column_definition_attributes *def,
                                        uchar *buff) const
  {
    def->frm_pack_basic(buff);
    def->frm_pack_charset(buff);
  }
  virtual bool
  Column_definition_attributes_frm_unpack(Column_definition_attributes *def,
                                          TABLE_SHARE *share,
                                          const uchar *buffer,
                                          LEX_CUSTRING *gis_options) const
  {
    def->frm_unpack_basic(buffer);
    return def->frm_unpack_charset(share, buffer);
  }
  virtual void make_sort_key(uchar *to, Item *item,
                             const SORT_FIELD_ATTR *sort_field,
                             Sort_param *param) const
  {
    DBUG_ASSERT(item->type_handler() == this);
    NativeBufferInet6 tmp;
    item->val_native_result(current_thd, &tmp);
    if (item->maybe_null)
    {
      if (item->null_value)
      {
        memset(to, 0, Inet6::binary_length() + 1);
        return;
      }
      *to++= 1;
    }
    DBUG_ASSERT(!item->null_value);
    DBUG_ASSERT(Inet6::binary_length() == tmp.length());
    DBUG_ASSERT(Inet6::binary_length() == sort_field->length);
    memcpy(to, tmp.ptr(), tmp.length());
  }
  virtual void sortlength(THD *thd,
                          const Type_std_attributes *item,
                          SORT_FIELD_ATTR *attr) const
  {
    attr->length= Inet6::binary_length();
    attr->suffix_length= 0;
  }
  virtual uint32 max_display_length(const Item *item) const
  {
    return Inet6::max_char_length();
  }
  virtual uint32 calc_pack_length(uint32 length) const
  {
    return Inet6::binary_length();
  }
  virtual void Item_update_null_value(Item *item) const
  {
    NativeBufferInet6 tmp;
    item->val_native(current_thd, &tmp);
  }
  virtual bool Item_save_in_value(THD *thd, Item *item, st_value *value) const
  {
    // QQ: share this code
    value->m_type= DYN_COL_STRING;
    String *str= item->val_str(&value->m_string);
    if (str != &value->m_string && !item->null_value)
      value->m_string.set(str->ptr(), str->length(), str->charset());
    return check_null(item, value);
  }
  virtual void Item_param_setup_conversion(THD *thd, Item_param *param) const
  {
    param->setup_conversion_string(thd, thd->variables.character_set_client);
  }
  virtual void Item_param_set_param_func(Item_param *param,
                                         uchar **pos, ulong len) const
  {
    param->set_param_str(pos, len);
  }
  virtual bool Item_param_set_from_value(THD *thd,
                                         Item_param *param,
                                         const Type_all_attributes *attr,
                                         const st_value *val) const
  {
    param->unsigned_flag= false;//QQ
    param->setup_conversion_string(thd, attr->collation.collation);
    /*
      Exact value of max_length is not known unless data is converted to
      charset of connection, so we have to set it later.
    */
    return param->set_str(val->m_string.ptr(), val->m_string.length(),
                          attr->collation.collation,
                          attr->collation.collation);
  }
  virtual bool Item_param_val_native(THD *thd,
                                     Item_param *item,
                                     Native *to) const
  {
    StringBufferInet6 buffer;
    String *str= item->val_str(&buffer);
    if (!str)
      return true;
    Inet6_null tmp(str->ptr(), str->length(), str->charset());
    return tmp.is_null() || tmp.to_native(to);
  }
  virtual bool Item_send(Item *item, Protocol *p, st_value *buf) const
  {
    return Item_send_str(item, p, buf);
  }
  virtual int Item_save_in_field(Item *item, Field *field,
                                 bool no_conversions) const
  {
    if (field->type_handler() == this)
    {
      NativeBuffer<MAX_FIELD_WIDTH> tmp;
      bool rc= item->val_native(current_thd, &tmp);
      if (rc || item->null_value)
        return set_field_to_null_with_conversions(field, no_conversions);
      field->set_notnull();
      return field->store_native(tmp);
    }
    return item->save_str_in_field(field, no_conversions);
  }

  virtual String *print_item_value(THD *thd, Item *item, String *str) const
  {
    StringBufferInet6 buf;
    String *result= item->val_str(&buf);
    return !result ||
           str->realloc(name().length() + result->length() + 2) ||
           str->copy(name().ptr(), name().length(), &my_charset_latin1) ||
           str->append('\'') ||
           str->append(result->ptr(), result->length()) ||
           str->append('\'') ?
           NULL :
           str;
  }

  /**
    Check if
      WHERE expr=value AND expr=const
    can be rewritten as:
      WHERE const=value AND expr=const

    "this" is the comparison handler that is used by "target".

    @param target       - the predicate expr=value,
                          whose "expr" argument will be replaced to "const".
    @param target_expr  - the target's "expr" which will be replaced to "const".
    @param target_value - the target's second argument, it will remain unchanged.
    @param source       - the equality predicate expr=const (or expr<=>const)
                          that can be used to rewrite the "target" part
                          (under certain conditions, see the code).
    @param source_expr  - the source's "expr". It should be exactly equal to
                          the target's "expr" to make condition rewrite possible.
    @param source_const - the source's "const" argument, it will be inserted
                          into "target" instead of "expr".
  */
  virtual bool
  can_change_cond_ref_to_const(Item_bool_func2 *target,
                               Item *target_expr, Item *target_value,
                               Item_bool_func2 *source,
                               Item *source_expr, Item *source_const) const
  {
    return false;
  }
  virtual bool
  subquery_type_allows_materialization(const Item *inner,
                                       const Item *outer) const
  {
    return false;
  }
  /**
    Make a simple constant replacement item for a constant "src",
    so the new item can futher be used for comparison with "cmp", e.g.:
      src = cmp   ->  replacement = cmp

    "this" is the type handler that is used to compare "src" and "cmp".

    @param thd - current thread, for mem_root
    @param src - The item that we want to replace. It's a const item,
                 but it can be complex enough to calculate on every row.
    @param cmp - The src's comparand.
    @retval    - a pointer to the created replacement Item
    @retval    - NULL, if could not create a replacement (e.g. on EOM).
                 NULL is also returned for ROWs, because instead of replacing
                 a Item_row to a new Item_row, Type_handler_row just replaces
                 its elements.
  */
  virtual Item *make_const_item_for_comparison(THD *thd,
                                               Item *src,
                                               const Item *cmp) const
  {
    return NULL; //QQ
  }
  virtual Item_cache *Item_get_cache(THD *thd, const Item *item) const;

/*
  virtual Item_literal *create_literal_item(THD *thd,
                                            const char *str, size_t length,
                                            CHARSET_INFO *cs,
                                            bool send_error) const
  {
    DBUG_ASSERT(0);
    return NULL;
  }
*/

  virtual Item *create_typecast_item(THD *thd, Item *item,
                                     const Type_cast_attributes &attr) const;

/*
  virtual Item_copy *create_item_copy(THD *thd, Item *item) const;
*/
  virtual int cmp_native(const Native &a, const Native &b) const
  {
    DBUG_ASSERT(a.length() == Inet6::binary_length());
    DBUG_ASSERT(b.length() == Inet6::binary_length());
    return memcmp(a.ptr(), b.ptr(), Inet6::binary_length());
  }
  virtual bool set_comparator_func(Arg_comparator *cmp) const
  {
    return cmp->set_cmp_func_native();
  }
  virtual bool Item_const_eq(const Item_const *a, const Item_const *b,
                             bool binary_cmp) const
  {
    return false;//QQ
  }
  virtual bool Item_eq_value(THD *thd, const Type_cmp_attributes *attr,
                             Item *a, Item *b) const
  {
    Inet6_null na(a);
    Inet6_null nb(b);
    return !na.is_null() && !nb.is_null() && !na.cmp(nb);
  }
  virtual bool Item_hybrid_func_fix_attributes(THD *thd,
                                               const char *name,
                                               Type_handler_hybrid_field_type *h,
                                               Type_all_attributes *attr,
                                               Item **items,
                                               uint nitems) const
  {
    attr->Type_std_attributes::operator=(Type_std_attributes_inet6());
    h->set_handler(this);
    return false;
  }
  virtual bool Item_func_min_max_fix_attributes(THD *thd,
                                                Item_func_min_max *func,
                                                Item **items,
                                                uint nitems) const
  {
    return Item_hybrid_func_fix_attributes(thd, func->func_name(),
                                           func, func, items, nitems);

  }
  virtual bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
  {
    func->Type_std_attributes::operator=(Type_std_attributes_inet6());
    func->set_handler(this);
    return false;
  }
  virtual bool Item_sum_sum_fix_length_and_dec(Item_sum_sum *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }
  virtual bool Item_sum_avg_fix_length_and_dec(Item_sum_avg *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }
  virtual
  bool Item_sum_variance_fix_length_and_dec(Item_sum_variance *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }

  virtual bool Item_val_native_with_conversion(THD *thd, Item *item,
                                               Native *to) const
  {
    Inet6_null tmp(item);
    return tmp.is_null() || tmp.to_native(to);
  }
  virtual bool Item_val_native_with_conversion_result(THD *thd, Item *item,
                                                      Native *to) const
  {
    if (item->type_handler() == this)
      return item->val_native_result(thd, to);
    StringBufferInet6 buffer;
    String *str= item->str_result(&buffer);
    if (!str)
      return true;
    if (item->collation.collation == &my_charset_bin)
    {
      if (str->length() != Inet6::binary_length())
        return true;
      return to->copy(str->ptr(), str->length());
    }
    Inet6_null tmp(*str);
    if (tmp.is_null())
    {
      current_thd->push_warning_wrong_value(Sql_condition::WARN_LEVEL_WARN,
                                            "inet6",//QQ
                                            ErrConvString(str).ptr());
    }
    return tmp.is_null() || tmp.to_native(to);
  }

  virtual bool Item_val_bool(Item *item) const
  {
    NativeBufferInet6 tmp;
    if (item->val_native(current_thd, &tmp))
      return false;
    return !Inet6::only_zero_bytes(tmp.ptr(), tmp.length());
  }
  virtual void Item_get_date(THD *thd, Item *item,
                             Temporal::Warn *buff, MYSQL_TIME *ltime,
                             date_mode_t fuzzydate) const
  {
    set_zero_time(ltime, MYSQL_TIMESTAMP_TIME);
  }

  virtual longlong Item_val_int_signed_typecast(Item *item) const
  {
    DBUG_ASSERT(0);
    return 0;
  }

  virtual longlong Item_val_int_unsigned_typecast(Item *item) const
  {
    DBUG_ASSERT(0);
    return 0;
  }

  virtual String *Item_func_hex_val_str_ascii(Item_func_hex *item,
                                              String *str) const
  {
    NativeBufferInet6 tmp;
    if ((item->null_value= item->arguments()[0]->val_native(current_thd, &tmp)))
      return NULL;
    DBUG_ASSERT(tmp.length() == Inet6::binary_length());
    if (str->set_hex(tmp.ptr(), tmp.length()))
    {
      str->length(0);
      str->set_charset(item->collation.collation);
    }
    return str;
  }

  virtual
  String *Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                              String *str) const
  {
    NativeBufferInet6 native;
    if (item->val_native(current_thd, &native))
    {
      DBUG_ASSERT(item->null_value);
      return NULL;
    }
    DBUG_ASSERT(native.length() == Inet6::binary_length());
    Inet6_null tmp(native.ptr(), native.length());
    return tmp.is_null() || tmp.to_string(str) ? NULL : str;
  }
  virtual
  double Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *)
                                              const
  {
    return 0;
  }
  virtual
  longlong Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *)
                                               const
  {
    return 0;
  }
  virtual
  my_decimal *Item_func_hybrid_field_type_val_decimal(
                                              Item_func_hybrid_field_type *,
                                              my_decimal *to) const
  {
    my_decimal_set_zero(to);
    return to;
  }
  virtual
  void Item_func_hybrid_field_type_get_date(THD *,
                                            Item_func_hybrid_field_type *,
                                            Temporal::Warn *,
                                            MYSQL_TIME *to,
                                            date_mode_t fuzzydate) const
  {
    set_zero_time(to, MYSQL_TIMESTAMP_TIME);
  }
  // WHERE is Item_func_min_max_val_native???
  virtual
  String *Item_func_min_max_val_str(Item_func_min_max *func, String *str) const
  {
    Inet6_null tmp(func);
    return tmp.is_null() || tmp.to_string(str) ? NULL : str;
  }
  virtual
  double Item_func_min_max_val_real(Item_func_min_max *) const
  {
    return 0;
  }
  virtual
  longlong Item_func_min_max_val_int(Item_func_min_max *) const
  {
    return 0;
  }
  virtual
  my_decimal *Item_func_min_max_val_decimal(Item_func_min_max *,
                                            my_decimal *to) const
  {
    my_decimal_set_zero(to);
    return to;
  }
  virtual
  bool Item_func_min_max_get_date(THD *thd, Item_func_min_max*,
                                  MYSQL_TIME *to, date_mode_t fuzzydate) const
  {
    set_zero_time(to, MYSQL_TIMESTAMP_TIME);
    return false;
  }

  virtual bool
  Item_func_between_fix_length_and_dec(Item_func_between *func) const
  {
    return false;
  }
  virtual longlong
  Item_func_between_val_int(Item_func_between *func) const
  {
    return func->val_int_cmp_native();
  }

  virtual cmp_item *
  make_cmp_item(THD *thd, CHARSET_INFO *cs) const
  {
    return NULL;///QQQ
  }

  virtual in_vector *
  make_in_vector(THD *thd, const Item_func_in *func, uint nargs) const;

  virtual bool
  Item_func_in_fix_comparator_compatible_types(THD *thd, Item_func_in *func)
                                                                       const
  {
    if (func->compatible_types_scalar_bisection_possible())
    {
      return func->value_list_convert_const_to_int(thd) ||
             func->fix_for_scalar_comparison_using_bisection(thd);
    }
    return
      func->fix_for_scalar_comparison_using_cmp_items(thd,
                                                      1U << (uint) STRING_RESULT);
  }
  virtual bool
  Item_func_round_fix_length_and_dec(Item_func_round *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }
  virtual bool
  Item_func_int_val_fix_length_and_dec(Item_func_int_val *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }

  virtual bool
  Item_func_abs_fix_length_and_dec(Item_func_abs *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }

  virtual bool
  Item_func_neg_fix_length_and_dec(Item_func_neg *func) const
  {
    return Item_func_or_sum_illegal_param(func);
  }

  virtual bool
  Item_func_signed_fix_length_and_dec(Item_func_signed *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_func_unsigned_fix_length_and_dec(Item_func_unsigned *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_double_typecast_fix_length_and_dec(Item_double_typecast *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_decimal_typecast_fix_length_and_dec(Item_decimal_typecast *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_char_typecast_fix_length_and_dec(Item_char_typecast *item) const
  {
    item->fix_length_and_dec_str();
    return false;
  }
  virtual bool
  Item_time_typecast_fix_length_and_dec(Item_time_typecast *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_date_typecast_fix_length_and_dec(Item_date_typecast *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_datetime_typecast_fix_length_and_dec(Item_datetime_typecast *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_func_plus_fix_length_and_dec(Item_func_plus *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_func_minus_fix_length_and_dec(Item_func_minus *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_func_mul_fix_length_and_dec(Item_func_mul *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_func_div_fix_length_and_dec(Item_func_div *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Item_func_mod_fix_length_and_dec(Item_func_mod *item) const
  {
    return Item_func_or_sum_illegal_param(item);
  }
  virtual bool
  Vers_history_point_resolve_unit(THD *thd, Vers_history_point *point) const
  {
    point->bad_expression_data_type_error(name().ptr());
    return true;
  }
};


const Name Type_handler_inet6::m_name_inet6(STRING_WITH_LEN("inet6"));

Type_handler_inet6 type_handler_inet6;


bool Inet6::make_from_item(Item *item)
{
  if (item->type_handler() == &type_handler_inet6)
  {
    Native tmp(m_buffer, sizeof(m_buffer));
    bool rc= item->val_native(current_thd, &tmp);
    if (rc)
      return true;
    DBUG_ASSERT(tmp.length() == sizeof(m_buffer));
    if (tmp.ptr() != m_buffer)
      memcpy(m_buffer, tmp.ptr(), sizeof(m_buffer));
    return false;
  }
  StringBufferInet6 tmp;
  String *str= item->val_str(&tmp);
  if (!str)
    return true;
  if (str->charset() != &my_charset_bin)
  {
    bool rc= str_to_ipv6(str->ptr(), str->length(), str->charset());
    if (rc)
    {
      static Name name= type_handler_inet6.name();
      current_thd->push_warning_wrong_value(Sql_condition::WARN_LEVEL_WARN,
                                            name.ptr(),
                                            ErrConvString(str).ptr());
    }
    return rc;
  }
  if (str->length() != sizeof(m_buffer))
  {
    static Name name= type_handler_inet6.name();
    current_thd->push_warning_wrong_value(Sql_condition::WARN_LEVEL_WARN,
                                          name.ptr(),
                                          ErrConvString(str).ptr());
    return true;
  }
  DBUG_ASSERT(str->ptr() != m_buffer);
  memcpy(m_buffer, str->ptr(), sizeof(m_buffer));
  return false;
};


bool Inet6::make_from_field(Field *field)
{
  if (field->is_null())
    return true;
// QQ: Type_handler_inet6!!!
  String tmp(m_buffer, sizeof(m_buffer), &my_charset_bin);
  String *str= field->val_str(&tmp);
  if (!str)
    return true;
  if (str->charset() != &my_charset_bin)
    return str_to_ipv6(str->ptr(), str->length(), str->charset());
  if (str->length() != sizeof(m_buffer))
    return true;
  if (str->ptr() != m_buffer)
    memcpy(m_buffer, str->ptr(), sizeof(m_buffer));
  return false;
};


class Field_inet6: public Field
{
  static void set_min_value(char *ptr)
  {
    memset(ptr, 0, Inet6::binary_length());
  }
  static void set_max_value(char *ptr)
  {
    memset(ptr, 0xFF, Inet6::binary_length());
  }
  void store_warning(const ErrConv &str,
                     Sql_condition::enum_warning_level level)
  {
    static const Name type_name= type_handler_inet6.name();
    get_thd()->push_warning_truncated_value_for_field(level, type_name.ptr(),
                                                      str.ptr(), table->s,
                                                      field_name.str);
  }
  int set_null_with_warn(const ErrConv &str)
  {
    store_warning(str, Sql_condition::WARN_LEVEL_WARN);
    set_null();
    return 1;
  }
  int set_min_value_with_warn(const ErrConv &str)
  {
    store_warning(str, Sql_condition::WARN_LEVEL_WARN);
    set_min_value((char*) ptr);
    return 1;
  }
  int set_max_value_with_warn(const ErrConv &str)
  {
    store_warning(str, Sql_condition::WARN_LEVEL_WARN);
    set_max_value((char*) ptr);
    return 1;
  }

public:
  Field_inet6(const LEX_CSTRING *field_name_arg, const Record_addr &rec)
    :Field(rec.ptr(), Inet6::max_char_length(),
           rec.null_ptr(), rec.null_bit(), Field::NONE, field_name_arg)
  {
    flags|= BINARY_FLAG | UNSIGNED_FLAG;
  }
  Item_result result_type () const
  {
    return type_handler_inet6.result_type();
  }
  enum Item_result cmp_type () const
  {
    return type_handler_inet6.cmp_type();
  }
  enum_field_types type() const
  {
    return type_handler_inet6.field_type();
  }
  const Type_handler *type_handler() const { return &type_handler_inet6; }

  uint32 max_display_length() const { return field_length; }
  bool str_needs_quotes() { return true; }
  enum Derivation derivation(void) const { return DERIVATION_NUMERIC; }
  uint repertoire(void) const { return MY_REPERTOIRE_ASCII; }
  CHARSET_INFO *charset(void) const { return &my_charset_numeric; }
  const CHARSET_INFO *sort_charset(void) const { return &my_charset_bin; }
  /**
    This makes client-server protocol convert the value according
    to @@character_set_client.
  */
  bool binary() const { return false; }
  enum Item_result cast_to_int_type() const { return DECIMAL_RESULT; }
  enum ha_base_keytype key_type() const { return HA_KEYTYPE_BINARY; }

  uint is_equal(Create_field *new_field)
  {
    return new_field->type_handler() == type_handler();
  }
  bool eq_def(const Field *field) const
  {
    return Field::eq_def(field);
  }
  double pos_in_interval(Field *min, Field *max)
  {
    return pos_in_interval_val_str(min, max, 0);
  }
  int cmp(const uchar *a, const uchar *b)
  { return memcmp(a, b, pack_length()); }

  void sort_string(uchar *to, uint length)
  {
    DBUG_ASSERT(length == pack_length());
    memcpy(to, ptr, length);
  }
  uint32 pack_length() const
  {
    return Inet6::binary_length();
  }

  void sql_type(String &str) const
  {
    static Name name= type_handler_inet6.name();
    str.set_ascii(name.ptr(), name.length());
  }

  bool validate_value_in_record(THD *thd, const uchar *record) const
  {
    return false;
  }

  String *val_str(String *val_buffer,
                  String *val_ptr __attribute__((unused)))
  {
    //ASSERT_COLUMN_MARKED_FOR_READ;
    Inet6_null tmp((const char *) ptr, pack_length());
    return tmp.to_string(val_buffer) ? NULL : val_buffer;
  }

  my_decimal *val_decimal(my_decimal *to)
  {
    //ASSERT_COLUMN_MARKED_FOR_READ;
    my_decimal_set_zero(to);
    return to;
  }

  longlong val_int()
  {
    //ASSERT_COLUMN_MARKED_FOR_READ;
    return 0;
  }

  double val_real()
  {
    //ASSERT_COLUMN_MARKED_FOR_READ;
    return 0;
  }

  bool get_date(MYSQL_TIME *ltime, date_mode_t fuzzydate)
  {
    //ASSERT_COLUMN_MARKED_FOR_READ;
    set_zero_time(ltime, MYSQL_TIMESTAMP_TIME);
    return false;
  }

  bool val_bool(void)
  {
    //ASSERT_COLUMN_MARKED_FOR_READ;
    return !Inet6::only_zero_bytes((const char *) ptr, Inet6::binary_length());
  }

  int store_native(const Native &value)
  {
    //ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    DBUG_ASSERT(value.length() == Inet6::binary_length());
    memcpy(ptr, value.ptr(), value.length());
    return 0;
  }

  int store(const char *str, size_t length, CHARSET_INFO *cs)
  {
    //ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    Inet6_null tmp= cs == &my_charset_bin ?
                    Inet6_null(str, length) :
                    Inet6_null(str, length, cs);
    if (tmp.is_null())
    {
      return maybe_null() ?
             set_null_with_warn(ErrConvString(str, length, cs)) :
             set_min_value_with_warn(ErrConvString(str, length, cs));
    }
    tmp.to_binary((char *) ptr, Inet6::binary_length());
    return 0;
  }

  int store_hex_hybrid(const char *str, size_t length)
  {
    return store(str, length, &my_charset_bin);
  }

  int store_decimal(const my_decimal *num)
  {
    //ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    return set_min_value_with_warn(ErrConvDecimal(num));
  }

  int store(longlong nr, bool unsigned_flag)
  {
    //ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    return set_min_value_with_warn(
            ErrConvInteger(Longlong_hybrid(nr, unsigned_flag)));
  }

  int store(double nr)
  {
    //ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    return set_min_value_with_warn(ErrConvDouble(nr));
  }

  int store_time_dec(const MYSQL_TIME *ltime, uint dec)
  {
    //ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    return set_min_value_with_warn(ErrConvTime(ltime));
  }

  /*** Field conversion routines ***/
  int store_field(Field *from)
  {
    // INSERT INTO t1 (inet6_field) SELECT different_field_type FROM t2;
    return from->save_in_field(this);
  }
  int save_in_field(Field *to)
  {
    // INSERT INTO t2 (different_field_type) SELECT inet6_field FROM t1;
    switch (to->cmp_type()) {
    case INT_RESULT:
    case REAL_RESULT:
    case DECIMAL_RESULT:
    case TIME_RESULT:
    {
      my_decimal buff;
      return to->store_decimal(val_decimal(&buff));
    }
    case STRING_RESULT:
      return save_in_field_str(to);
    case ROW_RESULT:
      break;
    }
    DBUG_ASSERT(0);
    to->reset();
    return 0;
  }
  Copy_func *get_copy_func(const Field *from) const
  {
    // ALTER to INET6 from another field
    /*
    if (eq_def(from))
      return get_identical_copy_func();
    switch (from->cmp_type()) {
    case STRING_RESULT:
      return do_field_string;
    case TIME_RESULT:
      return do_field_temporal;
    case DECIMAL_RESULT:
      return do_field_decimal;
    case REAL_RESULT:
      return do_field_real;
    case INT_RESULT:
      return do_field_int;
    case ROW_RESULT:
      DBUG_ASSERT(0);
      break;
    }
    */
    return do_field_string;//QQ
  }

  bool memcpy_field_possible(const Field *from) const
  {
    // INSERT INTO t1 (inet6_field) SELECT field2 FROM t2;
    return type_handler() == from->type_handler();
  }


  /*** Optimizer routines ***/
  bool test_if_equality_guarantees_uniqueness(const Item *const_item) const
  {
    /*
      This condition:
        WHERE inet6_field=const
      should return a single distinct value only,
      as comparison is done according to INET6.
      But we need to implement get_equal_const_item() first.
    */
    return false; // TODO: implement get_equal_const_item()
  }
  bool can_be_substituted_to_equal_item(const Context &ctx,
                                        const Item_equal *item)
  {
    return false; // TODO: equal field propagation
  }
  Item *get_equal_const_item(THD *thd, const Context &ctx,
                             Item *const_item)
  {
    /*
      This should return Item_inet6_literal (which is not implemented yet)
    */
    return NULL; // TODO: equal expression propagation
  }
  bool can_optimize_keypart_ref(const Item_bool_func *cond,
                                const Item *item) const
  {
    /*
      Mixing of two different non-traditional types is currently prevented.
      This may change in the future. For example, INET4 and INET6
      data types can be made comparable.
    */
    DBUG_ASSERT(item->type_handler()->is_traditional_type() ||
                item->type_handler() == type_handler());
    return true;
  }
  /**
    Test if Field can use range optimizer for a standard comparison operation:
      <=, <, =, <=>, >, >=
    Note, this method does not cover spatial operations.
  */
  bool can_optimize_range(const Item_bool_func *cond,
                          const Item *item,
                          bool is_eq_func) const
  {
    // See the DBUG_ASSERT comment in can_optimize_keypart_ref()
    DBUG_ASSERT(item->type_handler()->is_traditional_type() ||
                item->type_handler() == type_handler());
    return true;
  }
  SEL_ARG *get_mm_leaf(RANGE_OPT_PARAM *prm, KEY_PART *key_part,
                       const Item_bool_func *cond,
                       scalar_comparison_op op, Item *value)
  {
    DBUG_ENTER("Field_inet6::get_mm_leaf");
    if (!can_optimize_scalar_range(prm, key_part, cond, op, value))
      DBUG_RETURN(0);
    int err= value->save_in_field_no_warnings(this, 1);
    if ((op != SCALAR_CMP_EQUAL && is_real_null()) || err < 0)
      DBUG_RETURN(&null_element);
    if (err > 0)
    {
      if (op == SCALAR_CMP_EQ || op == SCALAR_CMP_EQUAL)
        DBUG_RETURN(new (prm->mem_root) SEL_ARG_IMPOSSIBLE(this));
      DBUG_RETURN(NULL); /*  Cannot infer anything */
    }
    DBUG_RETURN(stored_field_make_mm_leaf(prm, key_part, op, value));
  }
  bool can_optimize_hash_join(const Item_bool_func *cond,
                                      const Item *item) const
  {
    return can_optimize_keypart_ref(cond, item);
  }
  bool can_optimize_group_min_max(const Item_bool_func *cond,
                                  const Item *const_item) const
  {
    return true;
  }

  /**********/
  uint size_of() const { return sizeof(*this); }
};


class Item_typecast_inet6: public Item_func
{
public:
  Item_typecast_inet6(THD *thd, Item *a) :Item_func(thd, a) {}

  const Type_handler *type_handler() const
  { return &type_handler_inet6; }

  enum Functype functype() const { return CHAR_TYPECAST_FUNC; }
  bool eq(const Item *item, bool binary_cmp) const
  {
    if (this == item)
      return true;
    if (item->type() != FUNC_ITEM ||
        functype() != ((Item_func*)item)->functype())
      return false;
    if (type_handler() != item->type_handler())
      return false;
    Item_typecast_inet6 *cast= (Item_typecast_inet6*) item;
    return args[0]->eq(cast->args[0], binary_cmp);
  }
  const char *func_name() const { return "cast_as_inet6"; }
  void print(String *str, enum_query_type query_type)
  {
    str->append(STRING_WITH_LEN("cast("));
    args[0]->print(str, query_type);
    str->append(STRING_WITH_LEN(" as inet6)"));
  }
  bool fix_length_and_dec()
  {
    Type_std_attributes::operator=(Type_std_attributes_inet6());
    return false;
  }
  String *val_str(String *to)
  {
    Inet6_null tmp(args[0]);
    return (null_value= tmp.is_null() || tmp.to_string(to)) ? NULL : to;
  }
  longlong val_int()
  {
    return 0;
  }
  double val_real()
  {
    return 0;
  }
  my_decimal *val_decimal(my_decimal *to)
  {
    my_decimal_set_zero(to);
    return to;
  }
  bool get_date(THD *thd, MYSQL_TIME *ltime, date_mode_t fuzzydate)
  {
    set_zero_time(ltime, MYSQL_TIMESTAMP_TIME);
    return false;
  }
  bool val_native(THD *thd, Native *to)
  {
    Inet6_null tmp(args[0]);
    return null_value= tmp.is_null() || tmp.to_native(to);
  }
  Item *get_copy(THD *thd)
  { return get_item_copy<Item_typecast_inet6>(thd, this); }
};


class Item_cache_inet6: public Item_cache
{
  NativeBufferInet6 m_value;
public:
  Item_cache_inet6(THD *thd)
   :Item_cache(thd, &type_handler_inet6)
  { }
  Item *get_copy(THD *thd)
  { return get_item_copy<Item_cache_inet6>(thd, this); }
  bool cache_value()
  {
    if (!example)
      return false;
    value_cached= true;
    null_value= example->val_native_with_conversion_result(current_thd,
                                                           &m_value,
                                                           type_handler());
    return true;
  }
  String* val_str(String *to)
  {
    if (!has_value())
      return NULL;
    Inet6_null tmp(m_value.ptr(), m_value.length());
    return tmp.is_null() || tmp.to_string(to) ? NULL : to;
  }
  my_decimal *val_decimal(my_decimal *to)
  {
    if (!has_value())
      return NULL;
    my_decimal_set_zero(to);
    return to;
  }
  longlong val_int()
  {
    if (!has_value())
      return 0;
    return 0;
  }
  double val_real()
  {
    if (!has_value())
      return 0;
    return 0;
  }
  longlong val_datetime_packed(THD *thd)
  {
    DBUG_ASSERT(0);
    if (!has_value())
      return 0;
    return 0;
  }
  longlong val_time_packed(THD *thd)
  {
    DBUG_ASSERT(0);
    if (!has_value())
      return 0;
    return 0;
  }
  bool get_date(THD *thd, MYSQL_TIME *ltime, date_mode_t fuzzydate)
  {
    if (!has_value())
      return true;
    set_zero_time(ltime, MYSQL_TIMESTAMP_TIME);
    return false;
  }
  bool val_native(THD *thd, Native *to)
  {
    if (!has_value())
      return true;
    return to->copy(m_value.ptr(), m_value.length());
  }
};


class Item_inet6_literal: public Item_literal
{
  Inet6 m_value;
public:
  Item_inet6_literal(THD *thd)
   :Item_literal(thd),
    m_value(Inet6_null("::", 2, &my_charset_latin1))
  { }
  const Type_handler *type_handler() const { return &type_handler_inet6; }
  longlong val_int()
  {
    return 0;
  }
  double val_real()
  {
    return 0;
  }
  String *val_str(String *to)
  {
    return m_value.to_string(to) ? NULL : to;
  }
  my_decimal *val_decimal(my_decimal *to)
  {
    my_decimal_set_zero(to);
    return to;
  }
  bool get_date(THD *thd, MYSQL_TIME *ltime, date_mode_t fuzzydate)
  {
    set_zero_time(ltime, MYSQL_TIMESTAMP_TIME);
    return false;
  }
  bool val_native(THD *thd, Native *to)
  {
    return m_value.to_native(to);
  }
  void set_value(const Inet6 &value)
  {
    m_value= value;
  }
  Item *get_copy(THD *thd)
  { return get_item_copy<Item_inet6_literal>(thd, this); }
};


class in_inet6 :public in_vector
{
  Inet6 m_value;
  static int cmp_inet6(void *cmp_arg, Inet6 *a, Inet6 *b)
  {
    return a->cmp(*b);
  }
public:
  in_inet6(THD *thd, uint elements)
   :in_vector(thd, elements, sizeof(Inet6), (qsort2_cmp) cmp_inet6, 0),
    m_value(Inet6_null("::", 2, &my_charset_latin1))
  { }
  void set(uint pos, Item *item)
  {
    Inet6 *buff= &((Inet6 *) base)[pos];
    Inet6_null value(item);
    if (value.is_null())
      *buff= Inet6_null("::", 2, &my_charset_latin1);
    else
      *buff= value;
  }
  uchar *get_value(Item *item)
  {
    Inet6_null value(item);
    if (value.is_null())
      return 0;
    m_value= value;
    return (uchar *) &m_value;
  }
  Item* create_item(THD *thd)
  {
    return new (thd->mem_root) Item_inet6_literal(thd);
  }
  void value_to_item(uint pos, Item *item)
  {
    const Inet6 &buff= (((Inet6*) base)[pos]);
    static_cast<Item_inet6_literal*>(item)->set_value(buff);
  }
  const Type_handler *type_handler() const { return &type_handler_inet6; }
};


in_vector *
Type_handler_inet6::make_in_vector(THD *thd, const Item_func_in *func,
                                   uint nargs) const
{
  return new (thd->mem_root) in_inet6(thd, nargs);
}


Item *Type_handler_inet6::create_typecast_item(THD *thd, Item *item,
                                               const Type_cast_attributes &attr)
                                               const
{
  return new (thd->mem_root) Item_typecast_inet6(thd, item);
}


Item_cache *Type_handler_inet6::Item_get_cache(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_inet6(thd);
}


Field *
Type_handler_inet6::make_table_field_from_def(
                                     TABLE_SHARE *share,
                                     MEM_ROOT *mem_root,
                                     const LEX_CSTRING *name,
                                     const Record_addr &addr,
                                     const Bit_addr &bit,
                                     const Column_definition_attributes *attr,
                                     uint32 flags) const
{
  return new (mem_root) Field_inet6(name, addr);
}


Field *Type_handler_inet6::make_table_field(const LEX_CSTRING *name,
                                            const Record_addr &addr,
                                            const Type_all_attributes &attr,
                                            TABLE *table) const
{
  return new (table->in_use->mem_root) Field_inet6(name, addr);
}


Field *Type_handler_inet6::make_conversion_table_field(TABLE *table,
                                                       uint metadata,
                                                       const Field *target)
                                                       const
{
  const Record_addr tmp(NULL, Bit_addr(true));
  return new (table->in_use->mem_root) Field_inet6(&empty_clex_str, tmp);
}


/***************************************************************/

// QQ: This code should move to sql_type.cc

const Type_handler *
Type_handler_data::handler_by_name(const LEX_CSTRING &name) const
{
  return &type_handler_inet6;
}

bool Type_handler_data::init2()
{
  return
    m_type_aggregator_for_result.add(&type_handler_inet6,
                                     &type_handler_null,
                                     &type_handler_inet6) ||
    m_type_aggregator_for_result.add(&type_handler_inet6,
                                     &type_handler_inet6,
                                     &type_handler_inet6) ||
    m_type_aggregator_for_result.add(&type_handler_inet6,
                                     &type_handler_varchar,
                                     &type_handler_inet6) ||
    m_type_aggregator_for_result.add(&type_handler_inet6,
                                     &type_handler_hex_hybrid,
                                     &type_handler_inet6) ||
    m_type_aggregator_for_comparison.add(&type_handler_inet6,
                                         &type_handler_null,
                                         &type_handler_inet6) ||
    m_type_aggregator_for_comparison.add(&type_handler_inet6,
                                         &type_handler_long_blob,
                                         &type_handler_inet6) ||
    m_type_aggregator_for_comparison.add(&type_handler_inet6,
                                         &type_handler_inet6,
                                         &type_handler_inet6);
}
