package br.desafio.pitang.security.exception;

import lombok.AllArgsConstructor;

public class ErrorObject {

	private String message;
	private String field;
	private Object parameter;

	public ErrorObject() {
	}
	
	
	public ErrorObject(String message, String field, Object parameter) {
		super();
		this.message = message;
		this.field = field;
		this.parameter = parameter;
	}



	public String getMessage() {
		return message;
	}

	public String getField() {
		return field;
	}

	public Object getParameter() {
		return parameter;
	}

}
