#ifndef GTK4_COMPAT_H
#define GTK4_COMPAT_H

#include <gtk/gtk.h>

G_GNUC_UNUSED static void
_compat_dialog_response_cb (GtkDialog *dialog, gint response_id, gpointer data)
{
    int *p = data;
    *p = response_id;
}

G_GNUC_UNUSED static int
compat_dialog_run (GtkDialog *dialog)
{
    int response = GTK_RESPONSE_NONE;
    GMainLoop *loop = g_main_loop_new (NULL, FALSE);

    gulong response_id = g_signal_connect (dialog, "response",
                                           G_CALLBACK (_compat_dialog_response_cb),
                                           &response);
    gulong quit_id = g_signal_connect_swapped (dialog, "response",
                                               G_CALLBACK (g_main_loop_quit),
                                               loop);

    gtk_widget_set_visible (GTK_WIDGET (dialog), TRUE);
    gtk_window_present (GTK_WINDOW (dialog));
    g_main_loop_run (loop);

    g_signal_handler_disconnect (dialog, response_id);
    g_signal_handler_disconnect (dialog, quit_id);
    g_main_loop_unref (loop);

    return response;
}

G_GNUC_UNUSED static void
compat_widget_destroy (GtkWidget *widget)
{
    if (GTK_IS_WINDOW (widget))
        gtk_window_destroy (GTK_WINDOW (widget));
    else
        g_object_unref (widget);
}

#endif /* GTK4_COMPAT_H */
