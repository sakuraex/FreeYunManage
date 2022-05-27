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

//ע���û�
typedef struct ANTI_FREEYUN_REG
{
	std::string Account;	        //�˺�
	std::string Password;	        //����
	std::string QQ;		            //qq
	std::string Email;	            //����
	std::string Mobile;		        //�ֻ�
	std::string InvitingCode;		//������
	std::string AgentCode;		    //�����˺�
	

	ANTI_FREEYUN_REG(std::string Account, std::string Password, std::string QQ, std::string Email, std::string Mobile, std::string InvitingCode, std::string AgentCode)
	{
		this->Account      = Account;
		this->Password     = Password;
		this->QQ           = QQ;
		this->Email        = Email;
		this->Mobile       = Mobile;
		this->InvitingCode = InvitingCode;
		this->AgentCode    = AgentCode;
	}
	ANTI_FREEYUN_REG(std::string Account, std::string Password)
	{
		this->Account      = Account;
		this->Password     = Password;
		this->QQ           = "";
		this->Email        = "";
		this->Mobile       = "";
		this->InvitingCode = "";
		this->AgentCode    = "";
	}


}TAG_ANTI_FREEYUN_REG, * PTAG_ANTI_FREEYUN_REG;




class FreeYun
{
public:
	FreeYun();
	static FreeYun* GetpInstance();

	// @ ��ʼ��,����ɻ�ȡ������ĳ�ʼ����Ϣ����������桢����汾�š��Ƿ��и��µ���Ϣ
	std::tuple<bool,std::string, nlohmann::json> CloudInit(PTAG_ANTI_FREEYUN_INIT_INFO pInfo);

	// @ �û�ע��,�ýӿ��û��˺�ģʽ���˺�����ע��
	std::tuple<bool, std::string, nlohmann::json> CloudReg(PTAG_ANTI_FREEYUN_REG pInfo);

	/*
	*	@ �û���¼
	*	@->�ýӿ����������˺�����ĵ�½��������token��������Ҫ��֤�Ľӿڼ�Ȩ����
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudLogin(std::string Account, std::string Password, std::string md5);

	/*
	*	@ �û���ֵ
	*	@->�ýӿ������˺�ģʽ���˺ų�ֵ���������ڵ���ģʽ�ĳ�ֵ
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudPay(std::string Account, std::string cardNo);

	/*
	*	@ ��ѯ�û���Ϣ�ӿ�
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudQueryUserInfo(std::string Account);

	/*
	*	@ ���������
	*	@Param �˺�
	*	@Param ��������������� 1 = IP������ 2 = �����������
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudBlackLst(std::string Account,ULONG Type = 2);

	/*
	*	@ �޸�����
	*	@Param �˺�
	*	@Param ������ 
	*	@param ������
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudChangePassword(std::string Account, std::string oldPwd, std::string newPwd);

	// @ �˳���¼
	std::tuple<bool, std::string, nlohmann::json> CloudExit(std::string Account);

	/*
	*  @ ȡ�汾��Ϣ�����
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetVersionInfo();

	/*
	*	@ ȡ��ֵ���б�
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetPayCardList();

	/*
	*	@ ȡ�û�״̬�ӿ�
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetUserStatus(std::string Account);

	/*
	*	@ �ͻ��˿۵�
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUserSubPoint(std::string Account,int Value);

	/*
	*	@ ���ŵ�½
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudCardLogin(std::string Card, std::string md5);

	/*
	*	@ ִ��Զ�̴���
	*	@Param:�û����˺�
	*	@Param:��ǩ��
	*	@Param:js����������
	*	@Param:Զ��js����Ĳ���,���js�����޲����ɲ���磺function test(a,b);�����������д��ʽΪ ����������=����ֵ,��������=����ֵ��ע��ÿ��������ʽΪ����������=������ÿ��������Ӣ�ġ�����������֧�ֵ����������У�1�������͡�2���ı��͡�3�������͡�4��˫�����͡�5���������͡�(1=15,1=10��
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudExecTelnetCode(std::string Account, std::string lableName, std::string funcName, std::string params);

	/*
	*	@ ȡԶ�̱���
	*	@Param:�˺�
	*	@Param:Զ�̱�����
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetTeletVar(std::string Account, std::string keyName);

	/*
	*	@ ����ά��
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudHeartBeat(std::string Account);
	
	/*
	*	@ �޸Ļ�����
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudChangeMachine(std::string Account, std::string PassWord ="");

	/*
	*	@ ���Է���
	*	@Param:��������
	*	@Param:��ϵ��ʽ
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudFeedback(std::string Context, std::string links);

	/*
	*	@ �ϴ��ͻ����쳣��Ϣ
	*	@Param:�쳣��ǩ
	*	@Param:�쳣����
	*	@Param:����ϵͳ
	*	--���Է��� ����Ϊ�� ���Ǻ�̨��ʾ�ϴ��ɹ��ˣ�
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUpLoadClientExceptionInfo(std::string ExceptionTag, std::string Context,std::string operaSystem);

	/*
	*	@ ȡ�û�����Ȩ��
	*	�ýӿ�����ȡ��̨���õ��û���ɫ��Ӧ�ĳ���Ȩ�ޱ�ʶ������ע������ע���û�Ĭ��Ϊ��ͨ�û�Ȩ��Ϊ�գ�
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetUserPermission(std::string Account);

	/*
	*	@ Զ���㷨ת��
	*	@Param:�˺�
	*	@Param:Զ��ID
	*	@Param:����Ĳ���
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudRemoteAlgRelay(std::string Account,std::string remoteId,std::string params);

	/*
	*	@ ȡ�û���������
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUsersOnlineCount();
	
	/*
	*	@ �˺Ž��
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUserUnBind(std::string Account, std::string PassWord = "");



	//ȡ������
	int GetErrorCode();
	//ȡ������Ϣ
	std::string GetErrorStr(int ErrorCode);
	//@ ���ô������
	std::string SetErrorCode(int ErCode);
private:
	// @ RC4����
	std::string RC4Encrypt(std::string plaintext);
	// @ RC4����
	std::string RC4Decode(std::string Ciphertext);
	// @ MD5�ַ�������
	std::string GetStrMd5(std::string str);
	// @ post
	std::string Post(std::string str);
	// @ ��ȡPost��
	std::string GetPostPack(std::string data,std::string wtype, std::string csTime);
	// @ ��鷵�ص�json��Ϣ
	std::tuple<bool, std::string, nlohmann::json> DetectInfo(std::string data, std::tuple<bool, std::string, nlohmann::json> & Info,int Code);
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
	std::string m_Token;

	//��ֹJSON����
	template<class K, class V, class dummy_compare, class A>
	using my_workaround_fifo_map = nlohmann::fifo_map<K, V, nlohmann::fifo_map_compare<K>, A>;
	using FreeYun_json = nlohmann::basic_json<my_workaround_fifo_map>;

	static inline FreeYun* m_pInstance = nullptr;
};

