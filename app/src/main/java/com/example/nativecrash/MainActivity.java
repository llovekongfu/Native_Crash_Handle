package com.example.nativecrash;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final NativeCrashUtil nativeCrashUtil = new NativeCrashUtil();
        nativeCrashUtil.initNativeCrashCollect(this);
        final EditText tv = (EditText) findViewById(R.id.et_text);
        Button bt= (Button) findViewById(R.id.bt_text);
        bt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                int index = Integer.valueOf(tv.getText().toString().trim());
                int result = nativeCrashUtil.getStringFromJNI(index);
                tv.setText(String.valueOf(result));
            }
        });
    }

}
