package org.decentwallet.wallet.client;

import android.app.Activity;
import android.os.Bundle;

/** Activates the qualification test APK so Android 8 DocumentsUI can enumerate its provider. */
public final class QualificationDocumentProviderBootstrapActivity extends Activity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    finish();
  }
}
