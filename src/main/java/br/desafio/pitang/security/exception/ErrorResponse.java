package br.desafio.pitang.security.exception;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;

public class ErrorResponse {

	private String message;
	private int code;
	// private String status;
	// private String objectName;
	// private List<ErrorObject> errors;

	public ErrorResponse() {
		// TODO Auto-generated constructor stub
	}

	public ErrorResponse(String message, int code) {
		super();
		this.message = message;
		this.code = code;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}

}
