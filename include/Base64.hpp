/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#ifndef __TUPU_BASE64_H__
#define __TUPU_BASE64_H__

namespace TUPU
{

std::string base64_encode(const void * input, size_t input_len);
int base64_decode(const std::string & ascdata, void **buf_ptr, size_t *but_len);

} //namespace TUPU

#endif /* __TUPU_BASE64_H__ */