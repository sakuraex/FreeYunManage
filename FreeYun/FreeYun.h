#pragma once
#include <ACEBase.h>
#include <string>
#include "HttpClient.h"
#include <nlohmann/json.hpp>
#include <nlohmann/fifo_map.hpp>

//*	����ĳ�ʼ����Ϣ
typedef struct ANTI_FREEYUN_INIT_INFO
{
	std::string Version;	    //��ǰ�汾��
	std::string SecretKey;	    //�����Կ
	std::string Rc4Key;		    //Rc4��Կ
	std::string SaltKey;	    //ǩ����
	std::string AppId;		    //���ID
	std::string MachineID;		//������
	int   ServerLine;	        //��������·

	ANTI_FREEYUN_INIT_INFO(std::string Version, std::string SecretKey, std::string Rc4Key, std::string SaltKey, std::string AppId, std::string MachineID,int ServerLine)
	{	
		this->AppId      = AppId;
		this->Version    = Version;
		this->SecretKey  = SecretKey;
		this->Rc4Key     = Rc4Key;
		this->MachineID  = MachineID;
		this->SaltKey    = SaltKey;
		
		this->ServerLine = ServerLine;
	}
}TAG_ANTI_FREEYUN_INIT_INFO, * PTAG_ANTI_FREEYUN_INIT_INFO;



class FreeYun
{
public:
	bool CloudInit(PTAG_ANTI_FREEYUN_INIT_INFO pInfo);
	
	//ȡ������
	int GetErrorCode();
	//ȡ������Ϣ
	std::string GetErrorStr(int ErrorCode);

private:
	// @ RC4����
	std::string RC4Encrypt(std::string plaintext);
	// @ RC4����
	std::string RC4Decode(std::string Ciphertext);
	// @ MD5�ַ�������
	std::string GetStrMd5(std::string str);
	// @ post
	std::string Post(std::string str);
private:
	// �ɿ��Ǽ�����Щ�ַ���.���ǻ�������ܿ���
	std::string m_Version;
	std::string m_SecretKey;
	std::string m_Rc4Key;
	std::string m_SaltKey;
	std::string m_AppId;
	std::string m_MachineID;
	ULONG		m_ServerLine;
	HttpClient  m_HttpClient;
	int	        m_ErrorCode;


	//��ֹJSON����
	template<class K, class V, class dummy_compare, class A>
	using my_workaround_fifo_map = nlohmann::fifo_map<K, V, nlohmann::fifo_map_compare<K>, A>;
	using FreeYun_json = nlohmann::basic_json<my_workaround_fifo_map>;

};

