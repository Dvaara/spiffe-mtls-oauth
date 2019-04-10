package org.dvaara.spiffe.registration;

import spire.common.Common;

public class Main {

    public static void main(String[] args) {

        Common.RegistrationEntry.Builder registrationEntryBuilder = Common.RegistrationEntry.newBuilder();
        Common.RegistrationEntry registrationEntry = registrationEntryBuilder.build();
        System.out.println(registrationEntry.getSelectorsCount());
        System.out.println(registrationEntry.getAdmin());
        System.out.println("((((" + registrationEntry.getFederatesWithList());
    }

}