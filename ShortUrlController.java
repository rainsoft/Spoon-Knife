/**
 * ShortUrlController.java 2012-7-24
 */
package org.jasig.cas.server.web;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.server.CentralAuthenticationService;
import org.jasig.cas.server.authentication.Credential;
import org.jasig.cas.server.authentication.ShortUrlTokenCredential;
import org.jasig.cas.server.exception.ShortUrlNotFoundException;
import org.jasig.cas.server.exception.ShortUrlParamInvalidException;
import org.jasig.cas.server.login.LoginRequest;
import org.jasig.cas.server.login.LoginRequestFactory;
import org.jasig.cas.server.login.LoginResponse;
import org.jasig.cas.server.login.SessionCookieCreater;
import org.macula.Configuration;
import org.macula.base.security.util.SecurityUtils;
import org.macula.core.controller.BaseController;
import org.macula.core.mvc.annotation.OpenApi;
import org.macula.core.utils.HttpRequestUtils;
import org.macula.uim.base.domain.AccountType;
import org.macula.uim.base.domain.ShortUrl;
import org.macula.uim.base.domain.impl.JpaShortUrl;
import org.macula.uim.base.service.ShortUrlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.util.WebUtils;

/**
 * <p> <b>ShortUrlController</b> 短网址服务 </p>
 * 
 * @since 2012-7-24
 * @author zhengping_wang
 * @version $Id: ShortUrlController.java 3660 2012-10-30 08:20:44Z wzp $
 */
@Controller
@RequestMapping("surl")
public class ShortUrlController extends BaseController {

	@Autowired
	private ShortUrlService shortUrlService;

	@Autowired
	private LoginRequestFactory loginRequestFactory;

	@Autowired
	private CentralAuthenticationService centralAuthenticationService;

	@Autowired
	private SessionCookieCreater sessionCookieCreater;

	/**
	 * 创建短网址
	 */
	@RequestMapping(value = "/create", method = RequestMethod.POST)
	@OpenApi
	public String createShortUrl(HttpServletRequest request) {
		String longUrl = request.getParameter("longUrl");
		String toUserAccount = request.getParameter("toUserAccount");
		String accountType = request.getParameter("accountType");
		String appId = SecurityUtils.getUserDetails().getName();

		// 创建短网址
		JpaShortUrl jpaShortUrl = shortUrlService.create(appId, longUrl, toUserAccount,
				AccountType.valueOf(accountType));
		String shortUrl = jpaShortUrl != null ? jpaShortUrl.getShortUrl() : "";

		// 形成完整的短网址
		shortUrl = Configuration.getCasClientService() + "/surl/" + shortUrl;
		return shortUrl;
	}

	/**
	 * 访问短网址, https://uim/surl/{shortUrl}?surl_appId=xxx&surl_token=xxx
	 */
	@RequestMapping(value = "/{shortUrl}", method = RequestMethod.GET)
	public String accessShortUrl(@PathVariable("shortUrl") String shortUrl, NativeWebRequest request,
			HttpServletResponse response) {
		// 获取短网址的完整信息
		JpaShortUrl shortUrlEntity = shortUrlService.findByShortUrl(shortUrl);

		if (shortUrlEntity == null) {
			throw new ShortUrlNotFoundException();
		}

		// 1.
		// 从URL的参数获取appId、timestamp、token
		String appId = request.getParameter("surl_appId");
		// 获取时间戳
		String timestamp = request.getParameter("surl_t");
		// 获取Token(Token应该由Outlook或者Elink自动产生，通过cookie或者url传给ShortUrl)
		// Outlook需要将appId+userAccount+timestamp 做SHA1WithRSA签名
		String token = request.getParameter("surl_token");

		HttpServletRequest httpReq = request.getNativeRequest(HttpServletRequest.class);
		
		// 2.
		// 从surl_id中提取appId、timestamp、token，如果没有再分别提取相应的cookie
		// surl_id的格式是url_encode(appId___timestamp___token)
		if (StringUtils.isEmpty(appId) && StringUtils.isEmpty(timestamp) && StringUtils.isEmpty(token)) {
			Cookie cookie = WebUtils.getCookie(httpReq, "surl_id");
			if (null != cookie) {
				String id = cookie.getValue();
				if (StringUtils.isNotEmpty(id)) {
					try {
						id = URLDecoder.decode(id, "UTF-8");
						String[] ids = id.split("___");
						if (ids.length == 3) {
							appId = ids[0];
							timestamp = ids[1];
							token = ids[2];
						}
					} catch (UnsupportedEncodingException e) {
					}
				}
			}
		}

		// 3.
		// 上面没有获取到appId, timestamp, token，再从分别的cookie中提取
		if (StringUtils.isEmpty(appId)) {
			Cookie cookie = WebUtils.getCookie(httpReq, "surl_appId");
			if (null != cookie) {
				appId = cookie.getValue();
			}
		}

		if (StringUtils.isEmpty(timestamp)) {
			Cookie cookie = WebUtils.getCookie(httpReq, "surl_t");
			if (null != cookie) {
				timestamp = cookie.getValue();
			}
		}

		if (StringUtils.isEmpty(token)) {
			Cookie cookie = WebUtils.getCookie(httpReq, "surl_token");
			if (null != cookie) {
				token = cookie.getValue();
				if (StringUtils.isNotEmpty(token)) {
					try {
						token = URLDecoder.decode(token, "UTF-8");
					} catch (UnsupportedEncodingException e) {
					}
				}
			}
		}

		if (StringUtils.isEmpty(appId) || StringUtils.isEmpty(timestamp) || StringUtils.isEmpty(token)) {
			throw new ShortUrlParamInvalidException(shortUrl, appId, timestamp, token);
		}

		// 没有token或者appId则不去验证，直接redirect
		if (StringUtils.isNotEmpty(appId) && StringUtils.isNotEmpty(timestamp) && StringUtils.isNotEmpty(token)) {
			String errorMsg = doLogin(request, response, appId, timestamp, token, shortUrlEntity);
			if (errorMsg == null) {
				// 记录访问日志
				shortUrlEntity.setAccessCount(shortUrlEntity.getAccessCount() + 1);
				shortUrlEntity.setLastAccessIp(HttpRequestUtils.getRequestAddress(request
						.getNativeRequest(HttpServletRequest.class)));
				shortUrlService.saveShortUrl(shortUrlEntity);
			} else {
				// 显示错误页面
				httpReq.setAttribute("errorMsg", errorMsg);
				httpReq.setAttribute("redirectUrl",  shortUrlEntity.getLongUrl());
				return "/surl/error";
			}
		}
		return "redirect:" + shortUrlEntity.getLongUrl();
	}

	private String doLogin(NativeWebRequest request, HttpServletResponse response, String appId, String timestamp,
			String token, ShortUrl shortUrl) {
		LoginRequest loginRequest = loginRequestFactory.createLoginRequest(request);
		ShortUrlTokenCredential credentials = new ShortUrlTokenCredential(appId, timestamp, token, shortUrl,
				HttpRequestUtils.getRequestAddress(request.getNativeRequest(HttpServletRequest.class)));
		loginRequest.getCredentials().clear();
		loginRequest.getCredentials().add(credentials);
		LoginResponse loginResponse = centralAuthenticationService.login(loginRequest);
		if (loginResponse.getSession() != null) {
			loginRequest.setSessionId(loginResponse.getSession().getId());
			sessionCookieCreater.createSessionCookie(loginResponse, null, response);
			return null;
		}
		
		// 提取错误信息
		Map<Credential, List<GeneralSecurityException>> exceptions = loginResponse.getGeneralSecurityExceptions();
		StringBuffer expMsgBuffer = new StringBuffer("");
		if (null != exceptions) {
			List<GeneralSecurityException> expList = exceptions.get(credentials);
			for (GeneralSecurityException ex : expList) {
				expMsgBuffer.append(ex.getMessage()).append("<BR/>");
			}
		}
		return expMsgBuffer.toString();
	}
}
