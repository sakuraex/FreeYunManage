#pragma once
#include <ACEBase.h>
#include <string>
#include "HttpClient.h"
#include <nlohmann/json.hpp>
#include <nlohmann/fifo_map.hpp>

//*	传入的初始化信息
typedef struct ANTI_FREEYUN_INIT_INFO
{
	std::string Version;	    //当前版本号
	std::string SecretKey;	    //软件密钥
	std::string Rc4Key;		    //Rc4密钥
	std::string SaltKey;	    //签名盐
	std::string AppId;		    //软件ID
	std::string MachineID;		//机器码
	int   ServerLine;	        //服务器线路

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

//注册用户
typedef struct ANTI_FREEYUN_REG
{
	std::string Account;	        //账号
	std::string Password;	        //密码
	std::string QQ;		            //qq
	std::string Email;	            //邮箱
	std::string Mobile;		        //手机
	std::string InvitingCode;		//邀请码
	std::string AgentCode;		    //代理账号
	

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

	// @ 初始化,请求可获取到软件的初始化信息，如软件公告、软件版本号、是否有更新等信息
	std::tuple<bool,std::string, nlohmann::json> CloudInit(PTAG_ANTI_FREEYUN_INIT_INFO pInfo);

	// @ 用户注册,该接口用户账号模式的账号密码注册
	std::tuple<bool, std::string, nlohmann::json> CloudReg(PTAG_ANTI_FREEYUN_REG pInfo);

	/*
	*	@ 用户登录
	*	@->该接口请求用于账号密码的登陆，将返回token，用于需要认证的接口鉴权访问
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudLogin(std::string Account, std::string Password, std::string md5);

	/*
	*	@ 用户充值
	*	@->该接口用于账号模式的账号充值，不可用于单码模式的充值
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudPay(std::string Account, std::string cardNo);

	/*
	*	@ 查询用户信息接口
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudQueryUserInfo(std::string Account);

	/*
	*	@ 加入黑名单
	*	@Param 账号
	*	@Param 加入黑名单的类型 1 = IP黑名单 2 = 机器码黑名单
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudBlackLst(std::string Account,ULONG Type = 2);

	/*
	*	@ 修改密码
	*	@Param 账号
	*	@Param 旧密码 
	*	@param 新密码
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudChangePassword(std::string Account, std::string oldPwd, std::string newPwd);

	// @ 退出登录
	std::tuple<bool, std::string, nlohmann::json> CloudExit(std::string Account);

	/*
	*  @ 取版本信息或更新
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetVersionInfo();

	/*
	*	@ 取充值卡列表
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetPayCardList();

	/*
	*	@ 取用户状态接口
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetUserStatus(std::string Account);

	/*
	*	@ 客户端扣点
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUserSubPoint(std::string Account,int Value);

	/*
	*	@ 卡号登陆
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudCardLogin(std::string Card, std::string md5);

	/*
	*	@ 执行远程代码
	*	@Param:用户的账号
	*	@Param:标签名
	*	@Param:js函数方法名
	*	@Param:远程js代码的参数,如果js代码无参数可不填，如：function test(a,b);则这里参数填写格式为 ：参数类型=参数值,参数类型=参数值，注意每个参数格式为：数据类型=参数，每个参数用英文“，”隔开，支持的数据类型有：1、整数型、2、文本型、3、长整型、4、双精度型、5、单精度型。(1=15,1=10）
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudExecTelnetCode(std::string Account, std::string lableName, std::string funcName, std::string params);

	/*
	*	@ 取远程变量
	*	@Param:账号
	*	@Param:远程变量名
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetTeletVar(std::string Account, std::string keyName);

	/*
	*	@ 心跳维持
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudHeartBeat(std::string Account);
	
	/*
	*	@ 修改机器码
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudChangeMachine(std::string Account, std::string PassWord ="");

	/*
	*	@ 留言反馈
	*	@Param:留言内容
	*	@Param:联系方式
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudFeedback(std::string Context, std::string links);

	/*
	*	@ 上传客户端异常信息
	*	@Param:异常标签
	*	@Param:异常内容
	*	@Param:操作系统
	*	--测试发现 返回为空 但是后台显示上传成功了！
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUpLoadClientExceptionInfo(std::string ExceptionTag, std::string Context,std::string operaSystem);

	/*
	*	@ 取用户程序权限
	*	该接口用于取后台设置的用户角色对应的程序权限标识，（备注：所有注册用户默认为普通用户权限为空）
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudGetUserPermission(std::string Account);

	/*
	*	@ 远程算法转发
	*	@Param:账号
	*	@Param:远程ID
	*	@Param:请求的参数
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudRemoteAlgRelay(std::string Account,std::string remoteId,std::string params);

	/*
	*	@ 取用户在线人数
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUsersOnlineCount();
	
	/*
	*	@ 账号解绑
	*/
	std::tuple<bool, std::string, nlohmann::json> CloudUserUnBind(std::string Account, std::string PassWord = "");



	//取错误码
	int GetErrorCode();
	//取错误信息
	std::string GetErrorStr(int ErrorCode);
	//@ 设置错误代码
	std::string SetErrorCode(int ErCode);
private:
	// @ RC4加密
	std::string RC4Encrypt(std::string plaintext);
	// @ RC4解密
	std::string RC4Decode(std::string Ciphertext);
	// @ MD5字符串加密
	std::string GetStrMd5(std::string str);
	// @ post
	std::string Post(std::string str);
	// @ 获取Post包
	std::string GetPostPack(std::string data,std::string wtype, std::string csTime);
	// @ 检查返回的json信息
	std::tuple<bool, std::string, nlohmann::json> DetectInfo(std::string data, std::tuple<bool, std::string, nlohmann::json> & Info,int Code);
private:
	// 可考虑加密这些字符串.但是会带来解密开销
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

	//禁止JSON排序
	template<class K, class V, class dummy_compare, class A>
	using my_workaround_fifo_map = nlohmann::fifo_map<K, V, nlohmann::fifo_map_compare<K>, A>;
	using FreeYun_json = nlohmann::basic_json<my_workaround_fifo_map>;

	static inline FreeYun* m_pInstance = nullptr;
};

