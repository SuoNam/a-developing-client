#pragma once
/*
* Filename: sha256.hpp
* Author: L.Y.
* Brief: SHA256�㷨ʵ��
* Version: V1.0.0
* Update log:
*     1��20191108-20191113 V1.0.0
*         1�����ΰ汾��
* TODO:
* Attention:
*     1��������Ϣ��������ʱ���õ�������ָ����ʹ��SHA256���߼��ܹ��ߵõ�����ָ�ƿ��ܲ���ͬ��
*        ԭ�������ĵı��뷽ʽ��ͬ��
*/

#ifndef SHA256_HPP
#define SHA256_HPP

#include <stdint.h>

#include <string>
#include <vector>

namespace ly {

    //
    // \brief: SHA256�㷨ʵ��
    //
    class Sha256
    {
    public:
        //! Ĭ�Ϲ��캯��
        Sha256() {}

        //! ��������
        virtual ~Sha256() {}

        /** @brief: ʹ��SHA256�㷨����ȡ������Ϣ��ժҪ������ָ�ƣ�
        @param[in] message: ������Ϣ
        @param[out] _digest: ժҪ������ָ�ƣ�
        @return: �Ƿ�ɹ�
        */
        bool encrypt(const std::vector<uint8_t>& message,
            std::vector<uint8_t>* _digest);

        /** @brief: ��ȡʮ�����Ʊ�ʾ����ϢժҪ������ָ�ƣ�
        @param[in] message: ������Ϣ
        @return: ʮ�����Ʊ�ʾ����ϢժҪ������ָ�ƣ�
        */
        std::string getHexMessageDigest(const std::string& message);

    protected:
        /// SHA256�㷨�ж����6���߼����� ///
        inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) const;
        inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) const;
        inline uint32_t big_sigma0(uint32_t x) const;
        inline uint32_t big_sigma1(uint32_t x) const;
        inline uint32_t small_sigma0(uint32_t x) const;
        inline uint32_t small_sigma1(uint32_t x) const;

        /** @brief: SHA256�㷨��������Ϣ��Ԥ�������������������ء��͡����ӳ���ֵ��
        ����������: �ڱ���ĩβ������䣬�Ȳ���һ������Ϊ1��Ȼ�󶼲�0��ֱ�����������512ȡģ��������448����Ҫע����ǣ���Ϣ���������䡣
        ���ӳ���ֵ: ��һ��64λ����������ʾԭʼ��Ϣ�����ǰ����Ϣ���ĳ��ȣ������䲹���Ѿ�����������������Ϣ���档
        @param[in][out] _message: ���������Ϣ
        @return: �Ƿ�ɹ�
        */
        bool preprocessing(std::vector<uint8_t>* _message) const;

        /** @brief: ����Ϣ�ֽ��������64Byte��С�����ݿ�
        @param[in] message: ������Ϣ������Ϊ64Byte�ı���
        @param[out] _chunks: ������ݿ�
        @return: �Ƿ�ɹ�
        */
        bool breakTextInto64ByteChunks(const std::vector<uint8_t>& message,
            std::vector<std::vector<uint8_t>>* _chunks) const;

        /** @brief: ��64Byte��С�����ݿ飬�����64��4Byte��С���֡�
        �����㷨��ǰ16����ֱ�������ݿ�ֽ�õ���������������µ�����ʽ�õ���
                W[t] = small_sigma1(W[t-2]) + W[t-7] + small_sigma0(W[t-15]) + W[t-16]
        @param[in] chunk: �������ݿ飬��СΪ64Byte
        @param[out] _words: �����
        @return: �Ƿ�ɹ�
        */
        bool structureWords(const std::vector<uint8_t>& chunk,
            std::vector<uint32_t>* _words) const;

        /** @breif: ����64��4Byte��С���֣�����64��ѭ������
        @param[in] words: 64��4Byte��С����
        @param[in][out] _message_digest: ��ϢժҪ
        @return: �Ƿ�ɹ�
        */
        bool transform(const std::vector<uint32_t>& words,
            std::vector<uint32_t>* _message_digest) const;

        /** @brief: ������յĹ�ϣֵ������ָ�ƣ�
        @param[in] input: ����Ϊ32bit�Ĺ�ϣֵ
        @param[out] _output: ����Ϊ8bit�Ĺ�ϣֵ
        @return: �Ƿ�ɹ�
        */
        bool produceFinalHashValue(const std::vector<uint32_t>& input,
            std::vector<uint8_t>* _output) const;


    private:
        static std::vector<uint32_t> initial_message_digest_; // ��SHA256�㷨�еĳ�ʼ��ϢժҪ����Щ�����Ƕ���Ȼ����ǰ8��������ƽ������С������ȡǰ32bit������
        static std::vector<uint32_t> add_constant_; // ��SHA256�㷨�У��õ�64����������Щ�����Ƕ���Ȼ����ǰ64����������������С������ȡǰ32bit������
    };

    // ��������&ģ�溯���Ķ��� /

    inline uint32_t Sha256::ch(uint32_t x, uint32_t y, uint32_t z) const
    {
        return (x & y) ^ ((~x) & z);
    }

    inline uint32_t Sha256::maj(uint32_t x, uint32_t y, uint32_t z) const
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    inline uint32_t Sha256::big_sigma0(uint32_t x) const
    {
        return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
    }

    inline uint32_t Sha256::big_sigma1(uint32_t x) const
    {
        return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
    }

    inline uint32_t Sha256::small_sigma0(uint32_t x) const
    {
        return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
    }

    inline uint32_t Sha256::small_sigma1(uint32_t x) const
    {
        return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
    }

} // namespace ly

#endif // SHA256_HPP
