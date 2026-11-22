package org.decentwallet.wallet.client;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileNotFoundException;

/** Test-APK-only bounded staging provider for synthetic wallet-container bytes. */
public final class QualificationWalletFixtureStagingProvider extends ContentProvider {
  private static final String TARGET_PACKAGE = "org.decentwallet.wallet.client.qualification";

  private void enforceFixtureCaller() {
    Context context = getContext();
    if (context == null) {
      throw new SecurityException("fixture staging unavailable");
    }
    try {
      int targetUid = context.getPackageManager().getApplicationInfo(TARGET_PACKAGE, 0).uid;
      if (Binder.getCallingUid() == targetUid) {
        return;
      }
    } catch (PackageManager.NameNotFoundException ignored) {
      // Fail closed if the instrumentation target is not installed/visible.
    }
    throw new SecurityException("fixture staging caller denied");
  }

  private File fixtureFile() throws FileNotFoundException {
    if (getContext() == null) {
      throw new FileNotFoundException("provider context unavailable");
    }
    return new File(getContext().getCacheDir(), QualificationWalletDocumentProvider.FILE_NAME);
  }

  @Override
  public boolean onCreate() {
    return true;
  }

  @Override
  public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
      String sortOrder) {
    return null;
  }

  @Override
  public String getType(Uri uri) {
    return null;
  }

  @Override
  public Uri insert(Uri uri, ContentValues values) {
    return null;
  }

  @Override
  public int delete(Uri uri, String selection, String[] selectionArgs) {
    return 0;
  }

  @Override
  public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
    return 0;
  }

  @Override
  public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    enforceFixtureCaller();
    if (!"w".equals(mode) || !"document".equals(uri.getLastPathSegment())) {
      throw new FileNotFoundException("invalid fixture write request");
    }
    return ParcelFileDescriptor.open(
        fixtureFile(),
        ParcelFileDescriptor.MODE_CREATE
            | ParcelFileDescriptor.MODE_TRUNCATE
            | ParcelFileDescriptor.MODE_WRITE_ONLY);
  }

  @Override
  public Bundle call(String method, String arg, Bundle extras) {
    enforceFixtureCaller();
    if (!"clear".equals(method)) {
      throw new IllegalArgumentException("unsupported fixture operation");
    }
    try {
      File file = fixtureFile();
      if (file.exists() && !file.delete()) {
        throw new IllegalStateException("could not clear synthetic fixture");
      }
      Bundle result = new Bundle();
      result.putBoolean("ok", true);
      return result;
    } catch (FileNotFoundException failure) {
      throw new IllegalStateException("fixture staging unavailable", failure);
    }
  }
}
