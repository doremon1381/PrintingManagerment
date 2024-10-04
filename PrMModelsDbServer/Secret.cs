﻿namespace ServerDbModels
{
    /// <summary>
    /// Models a client secret with identifier and expiration
    /// </summary>    
    public class Secret
    {
        /// <summary>
        /// Gets or sets the description.
        /// </summary>
        /// <value>
        /// The description.
        /// </value>
        public string? Description { get; set; }

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>
        /// The value.
        /// </value>
        public string Value { get; set; } = default!;

        /// <summary>
        /// Gets or sets the expiration.
        /// </summary>
        /// <value>
        /// The expiration.
        /// </value>
        public DateTime? Expiration { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        public Secret()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="expiration">The expiration.</param>
        public Secret(string value, DateTime? expiration = null)
            : this()
        {
            Value = value;
            Expiration = expiration;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret" /> class.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="description">The description.</param>
        /// <param name="expiration">The expiration.</param>
        public Secret(string value, string description, DateTime? expiration = null)
            : this()
        {
            Description = description;
            Value = value;
            Expiration = expiration;
        }
    }
}
