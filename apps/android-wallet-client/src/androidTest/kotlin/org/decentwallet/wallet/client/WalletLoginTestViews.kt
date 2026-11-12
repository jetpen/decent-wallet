package org.decentwallet.wallet.client

import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView

internal object WalletLoginTestViews {
    fun texts(root: View): List<String> {
        val values = mutableListOf<String>()
        fun visit(view: View) {
            if (view is TextView) values += view.text.toString()
            if (view is ViewGroup) for (index in 0 until view.childCount) visit(view.getChildAt(index))
        }
        visit(root)
        return values
    }

    fun button(root: View, label: String): Button {
        if (root is Button && root.text == label) return root
        if (root is ViewGroup) for (index in 0 until root.childCount) {
            try { return button(root.getChildAt(index), label) } catch (_: NoSuchElementException) { }
        }
        throw NoSuchElementException(label)
    }
}
