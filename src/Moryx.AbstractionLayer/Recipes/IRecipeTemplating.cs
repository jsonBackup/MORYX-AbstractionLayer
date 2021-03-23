﻿namespace Moryx.AbstractionLayer.Recipes
{
    /// <summary>
    /// Additional interface for recipe that defines the template/source reference for cloned recipes
    /// TODO: Integrate this into IRecipe
    /// </summary>
    public interface IRecipeTemplating : IRecipe
    {
        /// <summary>
        /// Recipe reference that served as a template for this recipe
        /// </summary>
        long TemplateId { get; }
    }
}