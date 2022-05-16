/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#ifndef __TUPU_TIMAGE_H__
#define __TUPU_TIMAGE_H__

namespace TUPU
{

class TImage
{
    public:
        TImage();
        TImage(const TImage & img);
        virtual ~TImage();

        TImage & operator=(const TImage & img);

    public:
        //Set remote link of image
        void setURL(const std::string & url);
        //Set local path of image
        void setPath(const std::string & filepath);
        //Set binary data of image
        void setBinary(const void * buf, size_t buf_len, const std::string & filename);
        //Set tag of image to classify images in recognition result 
        void setTag(const std::string & tag) { m_tag = tag; }
        //Set sequence ids
        void setSequenceId(const std::string & sequenceId) { m_sequenceId = sequenceId; }

        void setTimestamp(uint64_t ts);

    public:
        const std::string & url() const { return m_url; }
        const std::string & path() const { return m_path; }
        const void * buffer() const { return m_buffer; }
        size_t bufferLength() const { return m_len; }
        const std::string & filename() const { return m_filename; }
        const std::string & tag() const { return m_tag; }
        const std::string & sequenceId() const { return m_sequenceId; }
        const std::string time() const { return std::to_string(m_ts); }

    private:
        std::string m_url;
        std::string m_path;
        std::string m_tag;
        std::string m_sequenceId;
        uint64_t m_ts;
        void * m_buffer;
        size_t m_len;
        std::string m_filename;
}; //Class TImage

} //namespace TUPU

#endif /* __TUPU_TIMAGE_H__ */