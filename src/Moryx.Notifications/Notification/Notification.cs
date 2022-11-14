// Copyright (c) 2022, Phoenix Contact GmbH & Co. KG
// Licensed under the Apache License, Version 2.0

using System;

namespace Moryx.Notifications
{
    /// <summary>
    /// Base class of all notifications.
    /// </summary>
    public class Notification 
    {
        /// <summary>
        /// Unique identifier of this notification
        /// </summary>
        public virtual Guid Identifier { get; private set; }

        /// <summary>
        /// The severity of this notification
        /// </summary>
        public Severity Severity { get; set; }

        /// <summary>
        /// Optional title of this notification. Can be set by processor as well
        /// </summary>
        public string Title { get; set; }

        /// <summary>
        /// Message of this notification.
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// Sender of this notification. <see cref="INotificationSender"/>
        /// </summary>
        public string Sender { get; set; }

        /// <summary>
        /// Source of this notification. <see cref="INotificationSource"/>
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// Indicates is the notification can be acknowledged
        /// </summary>
        public bool IsAcknowledgable { get; set; }

        /// <summary>
        /// If null, the notification was not acknowledged.
        /// If not null, the notification was already acknowledged
        /// </summary>
        // TODO: AL6 remove explicit backing attribute for property
        private DateTime? _acknowledged;
        /// <inheritdoc />
        public virtual DateTime? Acknowledged
        {
            get => _acknowledged;
            set
            {
                if (_acknowledged is null)
                    _acknowledged = value;
                else
                    throw new InvalidOperationException("Tried to update time of acknowledgement.");
            }
        }

        /// <summary>
        /// Who or what acknowledged the notification, if it was acknowledged.
        /// <see cref="Acknowledged"/> shows if the notification has been acknowledged.
        /// </summary>
        // TODO: AL6 remove explicit backing attribute for property
        private string _acknowledger;
        /// <inheritdoc />
        public virtual string Acknowledger
        {
            get => _acknowledger;
            set
            {
                if (_acknowledger is null)
                    _acknowledger = value;
                else
                    throw new InvalidOperationException("Tried to update acknowledger.");
            }
        }

        /// <summary>
        /// Date of creation
        /// </summary>
        // TODO: AL6 Remove backing attribute for property and make property nullable
        private DateTime? _created;
        /// <inheritdoc />
        public virtual DateTime Created
        {
            get => _created ?? default(DateTime);
            set
            {
                if (_created is null)
                    _created = value;
                else
                    throw new InvalidOperationException("Tried to update creation time.");
            }
        }

        /// <summary>
        /// Creates a new notification
        /// </summary>
        public Notification()
        {
            Identifier = Guid.NewGuid();
        }

        /// <summary>
        /// Creates a new notification with title and message
        /// </summary>
        public Notification(string title, string message, Severity severity) : this()
        {
            Title = title;
            Message = message;
            Severity = severity;
        }

        /// <summary>
        /// Creates a new notification with title and message
        /// </summary>
        public Notification(string title, string message, Severity severity, bool isAcknowledgable) : this(title, message, severity)
        {
            IsAcknowledgable = isAcknowledgable;
        }


    }
}
