package org.decentwallet.wallet.client;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.DocumentsProvider;

import java.io.File;
import java.io.FileNotFoundException;


/** Qualification test APK's read-only DocumentsProvider selected through system DocumentsUI. */
public final class QualificationWalletDocumentProvider extends DocumentsProvider {
  public static final String FILE_NAME = "qualification-wallet-document.bin";

  private File source() throws FileNotFoundException {
    if (getContext() == null) {
      throw new FileNotFoundException("provider context unavailable");
    }
    return new File(getContext().getCacheDir(), FILE_NAME);
  }

  @Override
  public boolean onCreate() {
    return true;
  }

  @Override
  public Cursor queryRoots(String[] projection) {
    MatrixCursor cursor = new MatrixCursor(new String[] {
        DocumentsContract.Root.COLUMN_ROOT_ID,
        DocumentsContract.Root.COLUMN_DOCUMENT_ID,
        DocumentsContract.Root.COLUMN_TITLE,
        DocumentsContract.Root.COLUMN_FLAGS,
        DocumentsContract.Root.COLUMN_MIME_TYPES
    });
    cursor.addRow(new Object[] {"qualification-wallets", "root", "Qualification wallets", 0, "*/*"});
    return cursor;
  }

  @Override
  public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
    return documentCursor(documentId);
  }

  @Override
  public Cursor queryChildDocuments(String parentDocumentId, String[] projection, String sortOrder)
      throws FileNotFoundException {
    MatrixCursor cursor = new MatrixCursor(new String[] {
        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_MIME_TYPE,
        DocumentsContract.Document.COLUMN_FLAGS,
        DocumentsContract.Document.COLUMN_SIZE,
        DocumentsContract.Document.COLUMN_LAST_MODIFIED
    });
    if ("root".equals(parentDocumentId)) {
      cursor.addRow(new Object[] {
          "wallet", "synthetic-wallet.bin", "application/octet-stream", 0, source().length(), 0L
      });
    }
    return cursor;
  }

  private Cursor documentCursor(String documentId) throws FileNotFoundException {
    MatrixCursor cursor = new MatrixCursor(new String[] {
        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_MIME_TYPE,
        DocumentsContract.Document.COLUMN_FLAGS,
        DocumentsContract.Document.COLUMN_SIZE,
        DocumentsContract.Document.COLUMN_LAST_MODIFIED
    });
    if ("root".equals(documentId)) {
      cursor.addRow(new Object[] {
          "root", "Qualification wallets", DocumentsContract.Document.MIME_TYPE_DIR, 0, 0L, 0L
      });
    } else if ("wallet".equals(documentId)) {
      cursor.addRow(new Object[] {
          "wallet", "synthetic-wallet.bin", "application/octet-stream", 0, source().length(), 0L
      });
    } else {
      throw new FileNotFoundException("unknown qualification document");
    }
    return cursor;
  }

  @Override
  public String getDocumentType(String documentId) throws FileNotFoundException {
    if ("root".equals(documentId)) {
      return DocumentsContract.Document.MIME_TYPE_DIR;
    }
    if ("wallet".equals(documentId)) {
      return "application/octet-stream";
    }
    throw new FileNotFoundException("unknown qualification document");
  }

  @Override
  public String createDocument(String parentDocumentId, String mimeType, String displayName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteDocument(String documentId) {
    throw new UnsupportedOperationException();
  }

  @Override
  public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal)
      throws FileNotFoundException {
    if (!"r".equals(mode) || !"wallet".equals(documentId)) {
      throw new FileNotFoundException("unknown qualification document");
    }
    return ParcelFileDescriptor.open(source(), ParcelFileDescriptor.MODE_READ_ONLY);
  }
}
