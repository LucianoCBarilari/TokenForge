using System.Diagnostics;
using System.Reflection;

namespace TokenForge.Application.Common
{
    public class MapperUtil
    {
        /// <summary>
        /// Copies non-default property values from a 'newData' object to a 'sourceData' object.
        /// For each property in 'newData', if it has a value (not null for reference types, not default for value types),
        /// and the property exists and is writable in 'sourceData' with the same type, it overwrites the value in 'sourceData'.
        /// </summary>
        /// <typeparam name="TSource">The type of the object to be updated.</typeparam>
        /// <typeparam name="TNew">The type of the object containing new values.</typeparam>
        /// <param name="sourceData">The object to be updated.</param>
        /// <param name="newData">The object containing possible new values.</param>
        public Task<TSource> MapClass<TSource, TNew>(TSource sourceData, TNew newData)
        {
            if (sourceData == null)
                throw new ArgumentNullException(nameof(sourceData));

            if (newData == null)
                return Task.FromResult(sourceData); // No hay datos nuevos para mapear

            PropertyInfo[] newProperties = typeof(TNew).GetProperties(BindingFlags.Public | BindingFlags.Instance);

            foreach (PropertyInfo newProp in newProperties)
            {
                try
                {
                    // 1. Verificar si la propiedad se puede leer
                    if (!newProp.CanRead)
                        continue;

                    // 2. Obtener la propiedad correspondiente en el source
                    PropertyInfo sourceProp = typeof(TSource).GetProperty(newProp.Name, BindingFlags.Public | BindingFlags.Instance);
                    if (sourceProp == null || !sourceProp.CanWrite)
                        continue;

                    // 3. Verificar compatibilidad de tipos
                    if (sourceProp.PropertyType != newProp.PropertyType)
                        continue;

                    // 4. Obtener el valor nuevo
                    object newValue = newProp.GetValue(newData);

                    // 5. Determinar si el valor nuevo debe ser aplicado
                    if (ShouldUpdateValue(newValue, newProp.PropertyType))
                    {
                        sourceProp.SetValue(sourceData, newValue);
                    }
                }
                catch (Exception ex)
                {
                    // Loggear error si es necesario
                    Debug.WriteLine($"Error mapping property {newProp.Name}: {ex.Message}");
                }
            }

            return Task.FromResult(sourceData);
        }

        private bool ShouldUpdateValue(object value, Type propertyType)
        {
            if (value == null)
                return false;

            // Manejo especial para strings
            if (propertyType == typeof(string))
                return !string.IsNullOrWhiteSpace((string)value);

            // Manejo para tipos por valor (value types)
            if (propertyType.IsValueType)
            {
                object defaultValue = Activator.CreateInstance(propertyType);
                return !Equals(value, defaultValue);
            }

            // Para otros tipos de referencia
            return true;
        }

    }

}

