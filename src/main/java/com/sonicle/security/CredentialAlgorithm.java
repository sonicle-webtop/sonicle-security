/*
 * CredentialEncodings.java
 *
 * Created on 12 agosto 2006, 11.39
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

/**
 *
 * @author gbulfon
 */
public enum CredentialAlgorithm {
    PLAIN("PLAIN"),
    SHA("SHA"),
    DES("DES");
    
    String name;
    
    CredentialAlgorithm(String name) {
        this.name=name;
    }
    
    public String toString() {
        return name;
    }
}
