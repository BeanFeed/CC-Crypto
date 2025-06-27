package com.beanfeed.cccrypto.apis;

import dan200.computercraft.api.lua.ILuaAPI;

public class CryptoAPI extends CryptoMethods implements ILuaAPI {
    @Override
    public String[] getNames() {
        return new String[] {"crypto"};
    }
}
