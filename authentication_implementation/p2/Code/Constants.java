package com;

public class Constants {

	// All the constants required in the Needham-Schroeder protocol
	public static String INITIATE_CONVERSATION = "Alice wants Bob";
	
	public static int ALICE = 1;
	public static int BOB = 2;
	public static int KDC = 3;
	
	public static String K_ALICE_KDC = "52084527516658884185208452751665888418";
	public static String K_BOB_KDC = "71078909518906601177107890951890660117";
	
	public static String CBC_ALGORITHM = "DESede/ECB/PKCS5Padding";
	public static String ECB_ALGORITHM = "DESede/ECB/PKCS5Padding";
	public static String CBC_ALGORITHM_WITHOUT_PADDING = "DESede/CBC/NoPadding";
	public static String ECB_ALGORITHM_WITHOUT_PADDING = "DESede/ECB/NoPadding";
	
}
